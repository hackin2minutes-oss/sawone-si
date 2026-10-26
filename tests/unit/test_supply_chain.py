"""Unit tests for the LLM supply-chain scanner (ai/supply_chain.py).

These tests are purely in-process (no Docker, no network) and cover:
  - trust_remote_code=True detection
  - from_pretrained without trust_remote_code=False
  - Unverified HuggingFace org
  - wget/curl without checksum
  - VCS / private-index pip installs
  - Unpinned AI deps in requirements.txt
  - Missing model provenance
  - Clean file (no findings)
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# ------------------------------------------------------------------ helpers


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def run(tmp_path, code_snippets=None, req_snippets=None, models=None):
    """Write files and run the supply-chain scanner."""
    from ai import supply_chain as SC  # noqa: PLC0415 — import after path is set

    for rel, src in (code_snippets or {}).items():
        _write(tmp_path, rel, src)
    for rel, src in (req_snippets or {}).items():
        _write(tmp_path, rel, src)
    ai_inventory = {"models": models or [], "components": [], "kinds": []}
    return SC.scan(tmp_path, ai_inventory)


# ------------------------------------------------------------------ tests

class TestTrustRemoteCode:
    def test_trust_true_flagged(self, tmp_path):
        findings = run(tmp_path, {"model_loader.py": "model = AutoModel.from_pretrained('org/m', trust_remote_code=True)\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-trust-remote-code" in ids

    def test_trust_false_clean(self, tmp_path):
        findings = run(tmp_path, {"ok.py": "model = AutoModel.from_pretrained('org/m', trust_remote_code=False)\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-trust-remote-code" not in ids
        # also no 'no-pin' warning because False is set
        assert "llm-supply-pretrained-no-pin" not in ids

    def test_pretrained_no_flag_warned(self, tmp_path):
        findings = run(tmp_path, {"load.py": "model = AutoModel.from_pretrained('some_org/some_model')\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-pretrained-no-pin" in ids


class TestUnverifiedModelSource:
    def test_personal_org_flagged(self, tmp_path):
        findings = run(tmp_path, {"dl.py":
            "m = AutoModel.from_pretrained('randomguy123/my-cool-model', trust_remote_code=False)\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-unverified-model-source" in ids

    def test_safe_org_clean(self, tmp_path):
        findings = run(tmp_path, {"dl.py":
            "m = AutoModel.from_pretrained('openai/whisper-large', trust_remote_code=False)\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-unverified-model-source" not in ids

    def test_meta_llama_clean(self, tmp_path):
        findings = run(tmp_path, {"dl.py":
            "m = AutoModel.from_pretrained('meta-llama/Llama-3-8B', trust_remote_code=False)\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-unverified-model-source" not in ids


class TestUnsignedDownload:
    def test_wget_no_hash_flagged(self, tmp_path):
        findings = run(tmp_path, {"get_model.sh":
            "wget https://example.com/model.gguf -O model.gguf\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-unsigned-download" in ids

    def test_wget_with_hash_clean(self, tmp_path):
        findings = run(tmp_path, {"get_model.sh":
            "wget https://example.com/model.gguf && sha256sum -c model.sha256\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-unsigned-download" not in ids

    def test_curl_no_hash_flagged(self, tmp_path):
        findings = run(tmp_path, {"setup.sh":
            "curl -LO https://example.com/model.safetensors\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-unsigned-download" in ids


class TestVCSAndPrivateIndex:
    def test_vcs_install_flagged(self, tmp_path):
        findings = run(tmp_path, {"install.sh":
            "pip install git+https://github.com/some/llm-lib.git@main\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-vcs-install" in ids

    def test_private_index_flagged(self, tmp_path):
        findings = run(tmp_path, {"install.sh":
            "pip install openai --extra-index-url https://my-private-pypi.example.com/simple\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-private-index" in ids

    def test_pypi_index_clean(self, tmp_path):
        findings = run(tmp_path, {"install.sh":
            "pip install openai\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-vcs-install" not in ids
        assert "llm-supply-private-index" not in ids


class TestUnpinnedDependencies:
    def test_unpinned_req_flagged(self, tmp_path):
        findings = run(tmp_path, req_snippets={"requirements.txt": "openai>=1.0\nfastapi\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-unpinned-ai-dep" in ids

    def test_pinned_req_clean(self, tmp_path):
        findings = run(tmp_path, req_snippets={"requirements.txt": "openai==1.31.0\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-unpinned-ai-dep" not in ids

    def test_non_ai_pkg_ignored(self, tmp_path):
        findings = run(tmp_path, req_snippets={"requirements.txt": "requests\nflask>=2\n"})
        ids = [f["id"] for f in findings]
        assert "llm-supply-unpinned-ai-dep" not in ids


class TestModelProvenance:
    def test_no_provenance_flagged(self, tmp_path):
        findings = run(tmp_path, models=[{"path": "models/my_model.gguf", "format": "gguf"}])
        ids = [f["id"] for f in findings]
        assert "llm-supply-no-provenance" in ids

    def test_model_card_present_clean(self, tmp_path):
        _write(tmp_path, "MODEL_CARD.md", "# My Model Card\n")
        findings = run(tmp_path, models=[{"path": "models/my_model.gguf", "format": "gguf"}])
        ids = [f["id"] for f in findings]
        assert "llm-supply-no-provenance" not in ids

    def test_no_models_no_provenance_finding(self, tmp_path):
        findings = run(tmp_path, models=[])
        ids = [f["id"] for f in findings]
        assert "llm-supply-no-provenance" not in ids


class TestCleanProject:
    def test_clean_python_file_no_findings(self, tmp_path):
        findings = run(tmp_path, {"app.py": (
            "import openai\n"
            "client = openai.OpenAI(api_key='test')\n"
            "model = AutoModel.from_pretrained('openai/gpt2', trust_remote_code=False)\n"
        )}, req_snippets={"requirements.txt": "openai==1.50.0\nfastapi==0.115.0\n"})
        blocking = [f for f in findings if f.get("severity") in ("HIGH", "CRITICAL")]
        assert not blocking, f"Unexpected HIGH/CRITICAL findings: {blocking}"
