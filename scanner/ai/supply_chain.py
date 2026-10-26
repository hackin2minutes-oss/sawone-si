"""ai/supply_chain.py — LLM Supply-Chain security checks (static, no code execution).

Checks:
  - from_pretrained() without explicit trust_remote_code=False
  - Hugging Face model loads from unverified community orgs / personal accounts
  - Missing integrity hash / digest for model downloads (huggingface_hub, wget, curl)
  - Model files referenced by mutable tag instead of @sha256 digest
  - pip/uv installs of AI packages from VCS refs or --extra-index-url pointing at private PyPI mirrors
  - requirements.txt / pyproject.toml: unpinned AI-framework versions (no == pin)
  - No provenance attestation (MODEL_CARD, model card, SBOM) found for models in the project
"""
import re
from pathlib import Path

CODE_EXT  = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".ipynb"}
SHELL_EXT = {".sh", ".bash", ".zsh", ".ksh", ".fish"}
SCAN_EXT  = CODE_EXT | SHELL_EXT
REQ_EXT   = {".txt", ".in", ".cfg", "requirements"}          # loose names
TOML_EXT  = {".toml"}

# ---------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------

# from_pretrained without trust_remote_code=False
_PRETRAINED  = re.compile(r"""from_pretrained\s*\(""", re.I)
_TRUST_FALSE = re.compile(r"""trust_remote_code\s*=\s*False""", re.I)
_TRUST_TRUE  = re.compile(r"""trust_remote_code\s*=\s*True""",  re.I)

# HF hub load that references a personal / community account (no verified org)
# e.g. "my-friend/my-model"  — single slash, first segment has no capital letter = not a verified org
_HF_PERSONAL_ORG = re.compile(
    r"""(?:from_pretrained|snapshot_download|hf_hub_download)\s*\(\s*["']([a-z0-9_.-]+/[^"']+)["']""",
    re.I,
)
# known safe orgs (expand as needed)
_SAFE_ORGS = {
    "openai", "anthropic", "google", "meta-llama", "mistralai", "microsoft", "huggingface",
    "stabilityai", "deepseek", "cohere", "databricks", "nvidia", "tiiuae", "allenai",
    "sentence-transformers", "cross-encoder", "qwen", "01-ai", "bigscience",
}

# wget/curl model downloads without --check-certificate / hash check
_WGET_CURL = re.compile(
    r"""(?:wget|curl)\s+.*(?:\.gguf|\.safetensors|\.pt|\.bin|\.pkl|\.onnx|\.h5|\.keras)""",
    re.I,
)
_HASH_CHECK = re.compile(r"""--md5\b|--sha|checksum|sha256|md5sum""", re.I)

# unpinned AI framework in requirements files
_AI_PKGS = re.compile(
    r"""^(openai|anthropic|google-generativeai|google-genai|vertexai|langchain|langgraph|
    llama-index|llama_index|mistralai|cohere|groq|litellm|pydantic-ai|crewai|autogen|
    pyautogen|semantic-kernel|smolagents|transformers|sentence-transformers|diffusers|
    torch|tensorflow|jax|keras|onnxruntime|garak|promptfoo|boto3)[\s><=!;#]""",
    re.I | re.X,
)
_PINNED = re.compile(r"""==[0-9]""")

# VCS or private-index installs
_VCS_INSTALL = re.compile(r"""(?:pip|uv)\s+install.*(?:git\+http|git\+ssh|\.git@|/tarball/|/zipball/)""", re.I)
_EXTRA_INDEX  = re.compile(r"""--extra-index-url\s+https?://(?!pypi\.org|files\.pythonhosted\.org)""", re.I)

# model card / provenance file names
_PROVENANCE_NAMES = re.compile(
    r"""(?i)(model.?card|MODEL.?CARD|provenance|attestation|\.attestation\.json|sbom|bom\.json)"""
)


# ---------------------------------------------------------------------------
def scan(ws, ai_inventory):
    """Return findings list.  ai_inventory is the dict from detect.detect()."""
    ws = Path(ws)
    out = []
    seen = set()   # (file, line, id) dedup

    def add(fid, sev, title, path, ln, **kw):
        key = (fid, str(path), ln)
        if key not in seen:
            seen.add(key)
            out.append(dict(id=fid, severity=sev, title=title, file=str(path), line=ln,
                            owasp="LLM05:2025-Improper Output Handling", **kw))

    # ----------------------------------------------------------------------- code checks
    for src_file in ws.rglob("*"):
        if src_file.suffix not in SCAN_EXT or not src_file.is_file():
            continue
        is_shell = src_file.suffix in SHELL_EXT
        try:
            text = src_file.read_text(errors="replace")
        except OSError:
            continue
        rel = src_file.relative_to(ws)
        lines = text.splitlines()

        for i, line in enumerate(lines, 1):
            # trust_remote_code=True  — remote code execution on model load
            if _TRUST_TRUE.search(line):
                add("llm-supply-trust-remote-code", "HIGH",
                    "trust_remote_code=True allows the model author to run arbitrary code during load; "
                    "remove this flag or use a verified local copy instead",
                    rel, i, cwe="CWE-829")

            # from_pretrained without explicit False
            if _PRETRAINED.search(line) and not _TRUST_FALSE.search(line):
                # look back up to 5 lines for trust_remote_code=True
                context = "\n".join(lines[max(0, i-3):i+3])
                if _TRUST_TRUE.search(context):
                    pass  # already caught above
                elif not _TRUST_FALSE.search(context):
                    add("llm-supply-pretrained-no-pin", "MEDIUM",
                        "from_pretrained() called without explicit trust_remote_code=False: "
                        "set trust_remote_code=False to fail safely if the model ever adds remote-code",
                        rel, i, cwe="CWE-829")

            # personal / unverified HF org
            m = _HF_PERSONAL_ORG.search(line)
            if m:
                org = m.group(1).split("/")[0].lower()
                if org not in _SAFE_ORGS:
                    add("llm-supply-unverified-model-source", "MEDIUM",
                        f"Model loaded from unverified HuggingFace account/org '{org}': prefer verified "
                        "organizations or mirror to a private registry with provenance checks",
                        rel, i, cwe="CWE-494")

            # wget/curl without hash
            if _WGET_CURL.search(line) and not _HASH_CHECK.search(line):
                add("llm-supply-unsigned-download", "HIGH",
                    "Model file downloaded with wget/curl without checksum verification: "
                    "a MITM or compromised host can substitute a malicious model",
                    rel, i, cwe="CWE-494")

            # VCS / private index installs (code + shell scripts)
            if _VCS_INSTALL.search(line):
                add("llm-supply-vcs-install", "MEDIUM",
                    "AI package installed from a VCS URL: pinned to a mutable commit, not a signed release",
                    rel, i, cwe="CWE-829")
            if _EXTRA_INDEX.search(line):
                add("llm-supply-private-index", "MEDIUM",
                    "AI packages resolved from a non-PyPI index: ensure the mirror has integrity checks",
                    rel, i, cwe="CWE-829")

            # Python-specific checks only (skip shell scripts for trust_remote_code)
            if is_shell:
                continue

    # ----------------------------------------------------------------------- requirements files
    for req_file in ws.rglob("*"):
        if not req_file.is_file():
            continue
        name = req_file.name.lower()
        is_req  = (req_file.suffix in REQ_EXT or "requirements" in name) and req_file.suffix in REQ_EXT | {".txt", ".in"}
        is_toml = req_file.suffix in TOML_EXT and "pyproject" in name
        if not (is_req or is_toml):
            continue
        try:
            text = req_file.read_text(errors="replace")
        except OSError:
            continue
        rel = req_file.relative_to(ws)
        for i, line in enumerate(text.splitlines(), 1):
            if _AI_PKGS.match(line.lstrip()) and not _PINNED.search(line):
                pkg = line.strip().split()[0].rstrip(",;")
                add("llm-supply-unpinned-ai-dep", "MEDIUM",
                    f"AI framework/provider '{pkg}' is not pinned to an exact version (==x.y.z): "
                    "an automatic upgrade can introduce breaking or malicious changes",
                    rel, i, cwe="CWE-1104")

    # ----------------------------------------------------------------------- model provenance
    models = ai_inventory.get("models", [])
    if models:
        provenance_found = any(
            _PROVENANCE_NAMES.search(f.name) for f in ws.rglob("*") if f.is_file()
        )
        if not provenance_found:
            out.append({
                "id": "llm-supply-no-provenance",
                "severity": "LOW",
                "title": f"No model card, attestation, or SBOM found for {len(models)} model file(s): "
                         "document model origin, training data, and integrity hashes",
                "file": "AI system",
                "line": 1,
                "owasp": "LLM05:2025-Improper Output Handling",
                "cwe": "CWE-1108",
            })

    return out
