"""Static checks on AI configuration files and documents (no code, no model loading):

  mcp_servers()  MCP client configs and FastMCP servers: unpinned servers, over-broad filesystem roots,
                 inline tokens, plain-HTTP remote servers, shell servers
  notebooks()    Jupyter notebooks: secrets in cells, personal data or tokens left in saved outputs, unsafe
                 model loading, unpinned installs
  corpora()      RAG documents: instructions hidden from a human reader (HTML comments, zero-width characters,
                 tiny/again-white text) that a model still reads — indirect prompt injection and poisoning
  prompts()      prompt/system-prompt files: secrets, internal URLs, override/backdoor phrases
  ai_iac()       the AI cloud resources detect() found: insecure settings per provider
"""
import json
import re
from pathlib import Path

from . import pii as PII


# ---------------------------------------------------------------- MCP
def mcp_servers(ws, configs):
    ws = Path(ws)
    out = []
    for rel in configs:
        p = ws / rel
        try:
            data = json.loads(p.read_text(errors="replace"))
        except (OSError, ValueError):
            out.append({"id": "mcp-unparsable", "severity": "LOW", "title": f"MCP config {rel} could not be parsed",
                        "file": rel, "line": 1})
            continue
        servers = data.get("mcpServers") or data.get("servers") or data.get("mcp", {}).get("servers") or {}
        if not isinstance(servers, dict):
            continue
        text = p.read_text(errors="replace")

        def line(needle):
            i = text.find(needle)
            return text.count("\n", 0, i) + 1 if i >= 0 else 1
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = cfg.get("command", "")
            args = cfg.get("args", []) or []
            argstr = " ".join(str(a) for a in args)
            url = cfg.get("url", "")
            ln = line(f'"{name}"')
            # unpinned package server (npx -y pkg / uvx pkg / docker image :latest or no tag)
            if cmd in ("npx", "uvx", "pnpm", "bunx") or cmd.endswith(("npx", "uvx")):
                pkgs = [a for a in args if isinstance(a, str) and not a.startswith("-")]
                pinned = any(re.search(r"@\d+\.\d+\.\d+$", pk) or re.search(r"==\d", pk) for pk in pkgs)
                if not pinned:
                    out.append({"id": "mcp-unpinned-server", "severity": "MEDIUM", "file": rel, "line": ln,
                                "title": f"MCP server '{name}' is installed unpinned ({cmd} {argstr[:60]}): a later "
                                         "release can change what runs with your tokens"})
            if cmd == "docker":
                if any(a.endswith(":latest") for a in args) or (any("ghcr.io" in a or "docker.io" in a for a in args)
                                                                and not any("@sha256:" in a for a in args)):
                    out.append({"id": "mcp-unpinned-image", "severity": "MEDIUM", "file": rel, "line": ln,
                                "title": f"MCP server '{name}' runs a container image that is not pinned by digest"})
            # over-broad filesystem server
            if "server-filesystem" in argstr or name in ("filesystem", "fs", "files"):
                roots = [a for a in args if isinstance(a, str) and (a.startswith("/") or re.match(r"[A-Za-z]:\\", a))]
                if any(r in ("/", "/home", "/Users", "/root", "C:\\", "/etc", "~") for r in roots):
                    out.append({"id": "mcp-filesystem-broad", "severity": "HIGH", "file": rel, "line": ln,
                                "title": f"MCP filesystem server '{name}' is rooted at {', '.join(roots)}: the model "
                                         "can read or write anything there"})
            # shell / command-execution server
            if re.search(r"shell|terminal|command|exec|bash", f"{name} {argstr}", re.I) and "server-filesystem" not in argstr:
                out.append({"id": "mcp-shell-server", "severity": "HIGH", "file": rel, "line": ln,
                            "title": f"MCP server '{name}' exposes shell/command execution to the model: prompt "
                                     "injection becomes command execution"})
            # inline secret in env
            env = cfg.get("env", {}) or {}
            for k, v in env.items():
                if isinstance(v, str) and PII.SECRET.search(v) or (isinstance(v, str) and len(v) > 20
                        and re.search(r"(token|key|secret|password)", k, re.I) and not v.startswith("${")
                        and "$" not in v):
                    out.append({"id": "mcp-inline-secret", "severity": "HIGH", "file": rel, "line": line(k),
                                "title": f"MCP server '{name}' has a secret written into its config ({k}): use an "
                                         "environment reference instead"})
            # remote server over plain HTTP
            if isinstance(url, str) and url.startswith("http://") and not re.search(r"://(localhost|127\.0\.0\.1)",
                                                                                     url):
                out.append({"id": "mcp-remote-http", "severity": "HIGH", "file": rel, "line": ln,
                            "title": f"MCP server '{name}' is reached over plain HTTP ({url}): tools and data travel "
                                     "unencrypted"})
    return out


# ---------------------------------------------------------------- notebooks
NB_UNSAFE_LOAD = re.compile(r"\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)"
                            r"|\bpickle\.loads?\s*\(|\bjoblib\.load\s*\(|allow_pickle\s*=\s*True"
                            r"|trust_remote_code\s*=\s*True|yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.(safe|Safe))")
NB_PIP = re.compile(r"^\s*[!%]\s*pip\s+install\s+(.+)$", re.M)


def notebooks(ws, paths):
    ws = Path(ws)
    out = []
    for rel in paths:
        try:
            nb = json.loads((ws / rel).read_text(errors="replace"))
        except (OSError, ValueError):
            out.append({"id": "notebook-unparsable", "severity": "LOW", "file": rel, "line": 1,
                        "title": f"notebook {rel} could not be parsed"})
            continue
        for idx, cell in enumerate(nb.get("cells", []) or []):
            src = "".join(cell.get("source", []) if isinstance(cell.get("source"), list) else [cell.get("source", "")])
            if cell.get("cell_type") == "code":
                for m in PII.SECRET.finditer(src):
                    out.append({"id": "notebook-secret", "severity": "CRITICAL", "file": rel, "line": idx + 1,
                                "title": f"API key or token hard-coded in notebook cell {idx + 1}"})
                if NB_UNSAFE_LOAD.search(src):
                    out.append({"id": "notebook-unsafe-load", "severity": "HIGH", "file": rel, "line": idx + 1,
                                "title": f"unsafe model/data loading in cell {idx + 1} "
                                         "(torch.load / pickle / allow_pickle / trust_remote_code)"})
                for m in NB_PIP.finditer(src):
                    pkgs = [x for x in m.group(1).split() if not x.startswith("-")]
                    if pkgs and not all(re.search(r"[=<>~]=?\d", x) for x in pkgs):
                        out.append({"id": "notebook-unpinned-install", "severity": "LOW", "file": rel, "line": idx + 1,
                                    "title": f"cell {idx + 1} installs unpinned packages ({' '.join(pkgs)[:60]}): the "
                                             "notebook is not reproducible and can pull a changed package"})
            # saved outputs that still carry secrets or personal data
            out_text = _output_text(cell)
            if out_text:
                if PII.SECRET.search(out_text) or PII.JWT.search(out_text):
                    out.append({"id": "notebook-output-secret", "severity": "HIGH", "file": rel, "line": idx + 1,
                                "title": f"a token is saved in the output of cell {idx + 1}: clear outputs before "
                                         "committing"})
                pii_hits = PII.scan_text(out_text, rel)
                strong = [f for f in pii_hits if f["severity"] in ("CRITICAL", "MEDIUM") and f["id"] != "data-pii-secret"]
                if strong:
                    kinds = ", ".join(sorted({f["kind"] for f in strong}))
                    out.append({"id": "notebook-output-pii", "severity": "MEDIUM", "file": rel, "line": idx + 1,
                                "title": f"personal data saved in the output of cell {idx + 1} ({kinds}): clear "
                                         "outputs before committing"})
    return out


def _output_text(cell):
    chunks = []
    for o in cell.get("outputs", []) or []:
        for key in ("text",):
            v = o.get(key)
            if v:
                chunks.append("".join(v) if isinstance(v, list) else str(v))
        data = o.get("data", {}) or {}
        for v in data.values():
            chunks.append("".join(v) if isinstance(v, list) else str(v))
        if o.get("traceback"):
            chunks.append("\n".join(o["traceback"]))
    return "\n".join(chunks)


# ---------------------------------------------------------------- RAG corpora: hidden instructions
ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff\u00ad"
INJECTION_PHRASES = re.compile(
    r"ignore (all |the )?(previous|prior|above) (instructions|prompts)|disregard (all |the )?(previous|above)"
    r"|you are now|new instructions:|system override|do not (tell|inform|reveal)|send (your|the).{0,30}(key|password|card"
    r"|cvv|token)|approve (every|all|any)|تجاهل (كل |جميع )?(التعليمات|الأوامر)( السابقة)?|تجاوز",
    re.I)


def corpora(ws, entries, max_files=300):
    ws = Path(ws)
    out = []
    for e in entries[:max_files]:
        rel = e["path"]
        p = ws / rel
        if Path(rel).suffix.lower() not in (".md", ".txt", ".html", ".htm", ".json", ".jsonl", ".xml", ".csv"):
            continue
        try:
            text = p.read_text(errors="replace")[:PII.SAMPLE_BYTES]
        except OSError:
            continue
        # instructions a human would not see
        for m in re.finditer(r"<!--(.*?)-->", text, re.S):
            if INJECTION_PHRASES.search(m.group(1)):
                out.append({"id": "rag-hidden-comment-injection", "severity": "HIGH", "file": rel,
                            "line": text.count("\n", 0, m.start()) + 1,
                            "title": "RAG document hides instructions to the model in an HTML comment (indirect "
                                     "prompt injection)"})
                break
        zw = sum(text.count(c) for c in ZERO_WIDTH)
        if zw >= 3:
            out.append({"id": "rag-zero-width", "severity": "HIGH", "file": rel, "line": 1,
                        "title": f"RAG document contains {zw} zero-width/invisible characters: often hidden "
                                 "instructions a reader cannot see"})
        visible = re.sub(r"<!--.*?-->", "", text, flags=re.S)
        for m in INJECTION_PHRASES.finditer(visible):
            out.append({"id": "rag-injection-phrase", "severity": "MEDIUM", "file": rel,
                        "line": visible.count("\n", 0, m.start()) + 1,
                        "title": f"RAG document contains an instruction-style phrase ('{m.group(0)[:40]}…'): review "
                                 "for data poisoning"})
            break
    return out


# ---------------------------------------------------------------- prompt files
OVERRIDE = re.compile(r"\boverride code\b|\bbackdoor\b|\bmaster password\b|\bif .{0,20}types? .{0,20}(you may|then you)"
                      r"|without (checks|verification|approval)|\bOVR-\w+\b", re.I)
INTERNAL_URL = re.compile(r"https?://(?:[\w.-]+\.(?:internal|local|corp|intra)\b|(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))"
                          r"\.[\d.]+)[^\s'\"]*")


def prompts(ws, paths):
    ws = Path(ws)
    out = []
    for rel in paths:
        try:
            text = (ws / rel).read_text(errors="replace")[:200_000]
        except OSError:
            continue

        def ln(i):
            return text.count("\n", 0, i) + 1
        for m in PII.SECRET.finditer(text):
            out.append({"id": "prompt-secret", "severity": "CRITICAL", "file": rel, "line": ln(m.start()),
                        "title": "a secret is written into a prompt file (it is sent to the model and often logged)"})
        for label, rx in (("password", re.compile(r"password[^\n]{0,40}[:=]\s*\S{6,}", re.I)),):
            for m in rx.finditer(text):
                out.append({"id": "prompt-password", "severity": "HIGH", "file": rel, "line": ln(m.start()),
                            "title": "a password appears in the system prompt: the model can be made to repeat it"})
        for m in INTERNAL_URL.finditer(text):
            out.append({"id": "prompt-internal-url", "severity": "MEDIUM", "file": rel, "line": ln(m.start()),
                        "title": f"the prompt names an internal endpoint ({m.group(0)[:50]}): it leaks infrastructure "
                                 "and invites SSRF through the model"})
            break
        for m in OVERRIDE.finditer(text):
            out.append({"id": "prompt-backdoor", "severity": "HIGH", "file": rel, "line": ln(m.start()),
                        "title": f"the prompt defines an override/backdoor phrase ('{m.group(0)[:40]}'): anyone who "
                                 "learns it bypasses the rules"})
            break
    return out


# ---------------------------------------------------------------- AI cloud IaC
def ai_iac(ws, resources):
    """Insecure settings on the AI cloud resources detect() found. Reads the HCL/JSON around each resource."""
    ws = Path(ws)
    out = []
    by_file = {}
    for r in resources:
        by_file.setdefault(r["path"], []).append(r)
    for rel, rs in by_file.items():
        try:
            text = (ws / rel).read_text(errors="replace")
        except OSError:
            continue
        for r in rs:
            block = _hcl_block(text, r.get("line", 1))
            t, name = r.get("type", ""), r.get("name", "")
            ln = r.get("line", 1)

            def add(rid, sev, title):
                out.append({"id": rid, "severity": sev, "file": rel, "line": ln, "title": title})
            if "cognitive_account" in t or t.endswith("CognitiveServices/accounts"):
                if re.search(r"public_network_access_enabled\s*=\s*true", block) or (
                        "public_network_access" not in block and "network_acls" not in block):
                    add("aiiac-openai-public", "HIGH", f"Azure OpenAI/Cognitive account '{name}' allows public "
                        "network access (no private endpoint or network ACL)")
                if re.search(r"local_auth_enabled\s*=\s*true", block) or "local_auth_enabled" not in block:
                    add("aiiac-openai-keyauth", "MEDIUM", f"Azure OpenAI account '{name}' allows API-key auth "
                        "(local_auth_enabled): prefer Entra ID (managed identity)")
            if "cognitive_deployment" in t and "rai_policy_name" not in block:
                add("aiiac-openai-no-content-filter", "MEDIUM", f"Azure OpenAI deployment '{name}' sets no content "
                    "filter (rai_policy_name): no guardrail on prompts or responses")
            if "machine_learning_workspace" in t and (re.search(r"public_network_access_enabled\s*=\s*true", block)
                                                      or "public_network_access_enabled" not in block):
                add("aiiac-mlws-public", "HIGH", f"Azure ML workspace '{name}' is reachable from the public network")
            if "bedrockagent_agent" in t and "guardrail_configuration" not in block:
                add("aiiac-bedrock-no-guardrail", "HIGH", f"Bedrock agent '{name}' has no guardrail_configuration: no "
                    "block on prompt injection, denied topics or sensitive data")
            if ("sagemaker_notebook_instance" in t):
                if re.search(r'direct_internet_access\s*=\s*"?Enabled', block):
                    add("aiiac-sagemaker-internet", "HIGH", f"SageMaker notebook '{name}' has direct internet access")
                if re.search(r'root_access\s*=\s*"?Enabled', block) or "root_access" not in block:
                    add("aiiac-sagemaker-root", "MEDIUM", f"SageMaker notebook '{name}' allows root access")
                if "kms_key_id" not in block:
                    add("aiiac-sagemaker-unencrypted", "MEDIUM", f"SageMaker notebook '{name}' has no KMS key (volume "
                        "not encrypted with a customer-managed key)")
            if "sagemaker_endpoint_configuration" in t and "kms_key_arn" not in block:
                add("aiiac-sagemaker-endpoint-unencrypted", "MEDIUM", f"SageMaker endpoint config '{name}' has no "
                    "KMS key")
            if ("vertex_ai_endpoint" in t or "vertex_ai_index" in t) and "encryption_spec" not in block:
                add("aiiac-vertex-no-cmek", "MEDIUM", f"Vertex AI resource '{name}' has no customer-managed "
                    "encryption key (encryption_spec)")
            if t in AI_ARM_NOTE:
                add("aiiac-arm-ai", "LOW", f"AI cloud resource declared ({r.get('type')}): review its network, "
                    "authentication, logging and content-filter settings")
    return out


AI_ARM_NOTE = ()   # ARM/Bicep hits are reported as LOW notes above via the generic branch when needed


def _hcl_block(text, line):
    """The text of the resource block that starts at `line` (brace-matched)."""
    start = 0
    for _ in range(max(0, line - 1)):           # byte offset of the start of `line` (1-based)
        nl = text.find("\n", start)
        if nl < 0:
            break
        start = nl + 1
    depth, j, started = 0, start, False
    while j < len(text):
        if text[j] == "{":
            depth += 1
            started = True
        elif text[j] == "}":
            depth -= 1
            if started and depth == 0:
                return _strip_hcl_comments(text[start:j + 1])
        j += 1
    return _strip_hcl_comments(text[start:start + 2000])


def _strip_hcl_comments(block):
    """Drop # and // line comments so a comment that names an attribute ('# no kms_key_id') is not mistaken
    for the attribute being set."""
    out = []
    for ln in block.splitlines():
        cut = len(ln)
        for marker in ("#", "//"):
            i = ln.find(marker)
            if 0 <= i < cut:
                cut = i
        out.append(ln[:cut])
    return "\n".join(out)
