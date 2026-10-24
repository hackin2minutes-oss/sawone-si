"""Model files examined as data, never loaded.

Loading a model can run code: a pickle (also PyTorch .pt, joblib, NumPy object arrays) executes whatever its
opcodes say, a Keras Lambda layer carries Python, a GGUF chat template is a Jinja2 template, and TorchScript
archives carry a pickle too. This module reads the bytes — pickle opcodes, zip entries, archive headers — and
reports dangerous constructs. It imports none of the ML libraries and deserialises nothing.

Each finding: id, severity, title, file, detail. Severity is HIGH/CRITICAL for anything that would run code,
MEDIUM for formats that are unsafe by nature (so a reviewer confirms provenance), LOW/INFO for notes.
"""
import json
import re
import struct
import zipfile
from pathlib import Path

# Importable targets that are dangerous to see in a pickle (module, name) -> why.
DANGEROUS = {
    ("os", "system"): "runs a shell command", ("os", "popen"): "runs a shell command",
    ("os", "execv"): "runs a program", ("os", "execve"): "runs a program", ("os", "spawnv"): "runs a program",
    ("subprocess", "run"): "runs a process", ("subprocess", "Popen"): "runs a process",
    ("subprocess", "call"): "runs a process", ("subprocess", "check_output"): "runs a process",
    ("subprocess", "getoutput"): "runs a shell command",
    ("builtins", "exec"): "executes code", ("builtins", "eval"): "evaluates code",
    ("builtins", "compile"): "compiles code", ("builtins", "__import__"): "imports a module",
    ("builtins", "getattr"): "reaches arbitrary attributes", ("builtins", "setattr"): "sets arbitrary attributes",
    ("importlib", "import_module"): "imports a module", ("pydoc", "pipepager"): "runs a shell command",
    ("posix", "system"): "runs a shell command", ("nt", "system"): "runs a shell command",
    ("webbrowser", "open"): "opens a URL", ("socket", "socket"): "opens a network socket",
    ("runpy", "_run_code"): "executes code", ("operator", "attrgetter"): "reaches arbitrary attributes",
}
SUSPECT_MODULES = ("os", "subprocess", "sys", "socket", "shutil", "requests", "urllib", "httpx", "ctypes",
                   "pty", "commands", "pickle", "base64", "codecs", "builtins", "importlib", "runpy", "pip")
STACK_GLOBAL_OPS = (b"c", b"\x93")      # GLOBAL, STACK_GLOBAL
REDUCE_OPS = (b"R", b"\x92", b"b", b"i")  # REDUCE, NEWOBJ, BUILD, INST


def _pickle_globals(data):
    """(module, name) referenced by GLOBAL/STACK_GLOBAL, and whether any REDUCE/BUILD runs them. Hand-rolled so
    an incomplete or hostile pickle is read without genpickle ever importing the names."""
    import pickletools
    globals_found, reduces, strings = [], 0, []
    last_two = []
    try:
        for op, arg, _pos in pickletools.genops(data):
            name = op.name
            if name == "GLOBAL":
                mod, _, attr = str(arg).partition(" ")
                globals_found.append((mod, attr))
            elif name == "STACK_GLOBAL" and len(last_two) >= 2:
                globals_found.append((str(last_two[-2]), str(last_two[-1])))
            elif name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "SHORT_BINSTRING", "BINSTRING"):
                strings.append(str(arg))
                last_two.append(str(arg))
                last_two = last_two[-2:]
            elif name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX", "BUILD", "INST", "OBJ"):
                reduces += 1
    except Exception:  # noqa: BLE001 — a truncated or crafted pickle still gives us the opcodes read so far
        pass
    return globals_found, reduces, strings


def scan_pickle_bytes(data, source, fmt="pickle"):
    out = []
    globals_found, reduces, strings = _pickle_globals(data)
    hits = []
    for mod, attr in globals_found:
        mod = {"__builtin__": "builtins", "exceptions": "builtins"}.get(mod, mod)   # Python-2 pickle names
        base = mod.split(".")[0]
        why = DANGEROUS.get((mod, attr)) or DANGEROUS.get((base, attr))
        if why:
            hits.append((f"{mod}.{attr}", why))
        elif base in SUSPECT_MODULES and base not in ("pickle",):
            hits.append((f"{mod}.{attr}", "imports a sensitive module"))
    if hits:
        shown = "; ".join(sorted({f"{g} ({w})" for g, w in hits})[:6])
        out.append({"id": "model-pickle-dangerous-import", "severity": "CRITICAL",
                    "title": f"{fmt} references code that runs on load: {shown}", "file": source,
                    "detail": shown})
    elif reduces:
        out.append({"id": "model-pickle-reduce", "severity": "HIGH",
                    "title": f"{fmt} runs object constructors on load (__reduce__/__setstate__): only load one you "
                             "produced", "file": source, "detail": f"{reduces} constructor call(s)"})
    else:
        out.append({"id": "model-pickle-format", "severity": "MEDIUM",
                    "title": f"{fmt} is a pickle: it can run code on load, so load it only from a source you trust",
                    "file": source, "detail": "no dangerous opcodes seen, but the format is unsafe by design"})
    b64 = [s for s in strings if len(s) > 120 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", s)]
    if b64 and hits:
        out.append({"id": "model-pickle-embedded-blob", "severity": "HIGH",
                    "title": f"{fmt} carries a large encoded blob next to code execution (often a hidden payload)",
                    "file": source, "detail": f"{len(b64)} blob(s)"})
    return out


def _zip_entries(path):
    """(names, open ZipFile) — the caller closes it (use `with z:`). (… , None) when it is not a zip."""
    try:
        z = zipfile.ZipFile(path)
        return z.namelist(), z
    except (zipfile.BadZipFile, OSError):
        return [], None


def scan_pytorch(path, source):
    """A .pt/.pth/.ckpt is usually a zip holding data.pkl; older ones are a bare pickle."""
    out = []
    names, z = _zip_entries(path)
    if z is None:
        return scan_pickle_bytes(Path(path).read_bytes(), source, "PyTorch checkpoint")
    with z:
        pkls = [n for n in names if n.endswith(".pkl")]
        for n in pkls:
            try:
                out += scan_pickle_bytes(z.read(n), f"{source}!{n}", "PyTorch checkpoint")
            except Exception:  # noqa: BLE001
                continue
        if any(n.endswith((".py", "constants.pkl")) or "code/" in n for n in names):
            out.append({"id": "model-torchscript-code", "severity": "HIGH",
                        "title": "TorchScript archive carries Python source (code/): review it", "file": source,
                        "detail": ", ".join(n for n in names if n.endswith(".py"))[:200]})
        if not pkls:
            out.append({"id": "model-pytorch-opaque", "severity": "LOW",
                        "title": "PyTorch archive with no data.pkl (unusual): verify its provenance", "file": source,
                        "detail": ", ".join(names[:5])})
    return out


def scan_numpy(path, source):
    """.npy/.npz: object arrays ('|O' dtype) hold a pickle; plain numeric arrays are safe."""
    out = []
    if Path(path).suffix.lower() == ".npz":
        names, z = _zip_entries(path)
        if z:
            with z:
                for n in names:
                    if b"'|O'" in z.read(n)[:128] or b'"|O"' in z.read(n)[:128]:
                        out.append({"id": "model-numpy-object-array", "severity": "HIGH",
                                    "title": f".npz member {n} is an object array (a pickle): it runs code on load",
                                    "file": source, "detail": n})
        return out
    head = Path(path).read_bytes()[:256]
    if head[:6] == b"\x93NUMPY" and (b"'|O'" in head or b'"|O"' in head or b"'O'" in head):
        out.append({"id": "model-numpy-object-array", "severity": "HIGH",
                    "title": ".npy is an object array (a pickle): np.load runs code unless allow_pickle=False",
                    "file": source, "detail": "dtype '|O'"})
    return out


def scan_keras(path, source):
    """Keras v3 (.keras zip) or HDF5 (.h5): a Lambda layer carries a serialised Python function."""
    out = []
    names, z = _zip_entries(path)
    if z is not None:
        with z:
            cfg = {}
            if "config.json" in names:
                try:
                    cfg = json.loads(z.read("config.json"))
                except ValueError:
                    cfg = {}
            if '"class_name": "Lambda"' in json.dumps(cfg) or "Lambda" in [l.get("class_name")
                    for l in _layers(cfg)]:
                out.append({"id": "model-keras-lambda", "severity": "HIGH",
                            "title": "Keras model has a Lambda layer: it carries Python that runs when the model is "
                                     "loaded with safe_mode disabled", "file": source, "detail": "Lambda layer"})
    else:
        raw = Path(path).read_bytes()
        if raw[:8] == b"\x89HDF\r\n\x1a\n" and (b"Lambda" in raw[:200000]):
            out.append({"id": "model-keras-lambda", "severity": "HIGH",
                        "title": "HDF5 Keras model references a Lambda layer (embedded Python)", "file": source,
                        "detail": "Lambda"})
        elif raw[:8] != b"\x89HDF\r\n\x1a\n":
            out.append({"id": "model-keras-unreadable", "severity": "LOW",
                        "title": "Keras/HDF5 file could not be parsed", "file": source, "detail": ""})
    return out


def _layers(cfg):
    try:
        return cfg.get("config", {}).get("layers", []) or []
    except AttributeError:
        return []


def scan_gguf(path, source):
    """GGUF: the tokenizer.chat_template is a Jinja2 template; one that reaches Python internals is an escape."""
    out = []
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return out
    if raw[:4] != b"GGUF":
        return [{"id": "model-gguf-bad-magic", "severity": "LOW", "title": "GGUF magic bytes missing", "file": source,
                 "detail": ""}]
    # the chat template is a UTF-8 value somewhere in the metadata; scan the readable text for escape patterns
    text = raw[:2_000_000].decode("utf-8", "replace")
    m = re.search(r"chat_template", text)
    window = text[m.start():m.start() + 4000] if m else ""
    danger = re.findall(r"__[a-z]+__|\bself\.|\bcycler\b|\bnamespace\b|\bos\b|popen|subprocess|lipsum|request\b",
                        window)
    if danger:
        out.append({"id": "model-gguf-template-escape", "severity": "HIGH",
                    "title": "GGUF chat template reaches Python internals (Jinja2 sandbox escape): it can run code "
                             "when the template is rendered", "file": source,
                    "detail": ", ".join(sorted(set(danger))[:6])})
    return out


def scan_safetensors(path, source):
    """safetensors is a safe format (data only). Report its metadata, never a code risk."""
    out = []
    try:
        with open(path, "rb") as f:
            n = struct.unpack("<Q", f.read(8))[0]
            if n > 100_000_000:
                return [{"id": "model-safetensors-bad-header", "severity": "LOW",
                         "title": "safetensors header length is implausible", "file": source, "detail": str(n)}]
            header = json.loads(f.read(n) or b"{}")
    except (OSError, ValueError, struct.error):
        return [{"id": "model-safetensors-unreadable", "severity": "LOW", "title": "safetensors header unreadable",
                 "file": source, "detail": ""}]
    meta = header.get("__metadata__", {})
    out.append({"id": "model-safetensors-ok", "severity": "INFO",
                "title": f"safetensors (safe format): {len([k for k in header if k != '__metadata__'])} tensors"
                         + (f", format {meta.get('format')}" if meta.get("format") else ""),
                "file": source, "detail": ""})
    return out


SCANNERS = {"pickle": scan_pickle_bytes, "pytorch": scan_pytorch, "joblib": None, "numpy": scan_numpy,
            "keras": scan_keras, "keras-h5": scan_keras, "gguf": scan_gguf, "safetensors": scan_safetensors,
            "onnx": None, "tflite": None, "tensorflow": None, "coreml": None, "torchserve": None,
            "llamafile": None}


def scan_file(path, fmt, source=None):
    source = source or str(path)
    path = Path(path)
    try:
        if fmt in ("pickle",):
            return scan_pickle_bytes(path.read_bytes(), source, "pickle")
        if fmt == "joblib":
            res = scan_pickle_bytes(path.read_bytes(), source, "joblib")
            for r in res:
                r["id"] = r["id"].replace("pickle", "joblib")
            return res
        fn = SCANNERS.get(fmt)
        if fn:
            return fn(path, source)
        # ONNX, TFLite, SavedModel, Core ML, .mar: data formats, but confirm provenance
        return [{"id": f"model-{fmt}-provenance", "severity": "INFO",
                 "title": f"{fmt} model: a data format (no code on load) — confirm where it came from",
                 "file": source, "detail": ""}]
    except Exception as e:  # noqa: BLE001 — a crafted file must be a finding, never a crash
        return [{"id": "model-unreadable", "severity": "MEDIUM",
                 "title": f"{fmt} model could not be parsed ({type(e).__name__}): treat as untrusted",
                 "file": source, "detail": str(e)[:160]}]


def scan_models(models):
    """models: the detect() inventory entries ({path, format, size}) resolved to absolute paths via .abs."""
    out = []
    for m in models:
        out += scan_file(m["abs"], m["format"], m["path"])
    return out
