"""Writes the model files of the vulnai fixture (tests/fixtures/vulnai/models). Deterministic; run it again only
when changing them. The "malicious" payloads only echo a message, and SawOne-SI never loads any of these files:
they are parsed as data to prove the model checks find what they should."""
import io
import json
import os
import pickle
import struct
import sys
import zipfile
from pathlib import Path

OUT = Path(__file__).resolve().parent / "vulnai" / "models"
MSG = "echo SawOne-SI fixture: loading this model would have run a command"


class _Cmd:
    def __reduce__(self):
        return (os.system, (MSG,))


class _Exec:
    def __reduce__(self):
        return (exec, ("import os; os.system(%r)" % MSG,))


def zinfo(name):
    z = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    z.compress_type = zipfile.ZIP_STORED
    return z


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    # 1. a plain pickle that runs a shell command on load
    (OUT / "classifier.pkl").write_bytes(pickle.dumps({"model": "logreg", "hook": _Cmd()}, protocol=4))
    # 2. a benign pickle saved as joblib: no code, but the format itself is unsafe from untrusted sources
    (OUT / "scaler.joblib").write_bytes(pickle.dumps({"mean": [0.1, 0.2], "scale": [1.0, 2.0]}, protocol=4))
    # 3. a PyTorch checkpoint (zip) whose data.pkl calls exec
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zinfo("model/data.pkl"), pickle.dumps({"state_dict": {}, "_meta": _Exec()}, protocol=2))
        z.writestr(zinfo("model/version"), "3\n")
        z.writestr(zinfo("model/byteorder"), "little")
    (OUT / "model.pt").write_bytes(buf.getvalue())
    # 4. a NumPy object array: .npy with a pickle inside
    hdr = "{'descr': '|O', 'fortran_order': False, 'shape': (2,), }"
    hdr += " " * (63 - (10 + len(hdr)) % 64) + "\n"
    body = pickle.dumps([1.5, _Cmd()], protocol=3)
    (OUT / "weights.npy").write_bytes(b"\x93NUMPY\x01\x00" + struct.pack("<H", len(hdr)) + hdr.encode() + body)
    # 5. a Keras v3 archive with a Lambda layer (its function is serialised Python bytecode)
    cfg = {"module": "keras", "class_name": "Sequential", "config": {"name": "gate", "layers": [
        {"module": "keras.layers", "class_name": "InputLayer", "config": {"batch_shape": [None, 4]}},
        {"module": "keras.layers", "class_name": "Lambda", "config": {"name": "hook", "function": {
            "class_name": "__lambda__", "config": {"code": "4wEAAAAAAAAAAAAAAAEAAAADAAAA8wwAAACXAHQAAAAAAAAAAABkAKYBAACrAQAA",
                                                   "defaults": None, "closure": None}}}},
        {"module": "keras.layers", "class_name": "Dense", "config": {"units": 1}}]}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zinfo("config.json"), json.dumps(cfg))
        z.writestr(zinfo("metadata.json"), json.dumps({"keras_version": "3.3.3"}))
    (OUT / "lambda.keras").write_bytes(buf.getvalue())
    # 6. a GGUF file whose chat template reaches Python internals (Jinja2 sandbox escape, CVE-2024-34359 class)
    def s(x):
        b = x.encode()
        return struct.pack("<Q", len(b)) + b
    kv = [("general.architecture", "llama"), ("general.name", "support-7b"),
          ("tokenizer.chat_template", "{% for m in messages %}{{ m.content }}{% endfor %}"
           "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}")]
    data = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", len(kv))
    for k, v in kv:
        data += s(k) + struct.pack("<I", 8) + s(v)
    (OUT / "chat.gguf").write_bytes(data)
    # 7. a clean safetensors file
    header = json.dumps({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
                         "__metadata__": {"format": "pt"}}).encode()
    (OUT / "safe.safetensors").write_bytes(struct.pack("<Q", len(header)) + header + struct.pack("<2f", 0.5, 1.5))
    (OUT / "config.yaml").write_text("threshold: 0.7\nlabels: [refund, shipping, other]\n")
    print("wrote", sorted(p.name for p in OUT.iterdir()))


if __name__ == "__main__":
    sys.exit(main())
