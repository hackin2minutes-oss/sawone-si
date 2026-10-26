"""SawOne-SI's analysers on the vulnai fixture: detection, model scan, PII, configs, and the AI rule pack."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ai import configs as CFG
from ai import detect as DET
from ai import modelscan as MS
from ai import pii as PII

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "tests" / "fixtures" / "vulnai"


def inv():
    return DET.detect(APP, exclude={".git"}, manifests=["requirements.txt", "web/package.json"])


def test_detection_finds_every_ai_kind():
    i = inv()
    assert set(i["kinds"]) >= {"llm-app", "rag", "agent", "mcp", "ml-model", "notebook", "training", "serving",
                               "ai-iac"}
    names = {c["name"] for c in i["components"]}
    assert {"OpenAI", "LangChain", "Hugging Face Hub", "Chroma", "FAISS", "Gradio", "MCP server"} <= names
    assert len(i["models"]) == 7 and i["notebooks"] == ["notebooks/explore.ipynb"]
    assert len(i["ai_iac"]) >= 6 and {im["product"] for im in i["ai_images"]} >= {"Ollama", "vLLM", "MLflow"}


def test_model_scan_classifies_every_format():
    res = {}
    for m in inv()["models"]:
        res[Path(m["path"]).name] = MS.scan_file(APP / m["path"], m["format"], m["path"])
    assert res["classifier.pkl"][0]["id"] == "model-pickle-dangerous-import"
    assert res["classifier.pkl"][0]["severity"] == "CRITICAL"
    assert res["model.pt"][0]["id"] == "model-pickle-dangerous-import"
    assert res["weights.npy"][0]["id"] == "model-numpy-object-array"
    assert res["lambda.keras"][0]["id"] == "model-keras-lambda"
    assert res["chat.gguf"][0]["id"] == "model-gguf-template-escape"
    assert res["scaler.joblib"][0]["id"] == "model-joblib-format"
    assert res["safe.safetensors"][0]["id"] == "model-safetensors-ok"
    assert res["safe.safetensors"][0]["severity"] == "INFO"


def test_safetensors_is_never_a_code_risk():
    r = MS.scan_file(APP / "models" / "safe.safetensors", "safetensors", "safe.safetensors")
    assert all(f["severity"] == "INFO" for f in r)


def test_pii_detects_saudi_identifiers_with_checksums():
    res = {f["id"]: f for f in PII.scan_files(APP, [{"path": "data/train.jsonl"}])}
    assert res["data-pii-sa-national-id"]["count"] == 5
    assert res["data-pii-iban"]["count"] == 5
    assert res["data-pii-credit-card"]["count"] == 1          # Luhn-valid only
    assert all("*" in s for f in res.values() for s in f["samples"])   # samples are redacted
    assert not any(ch.isdigit() for f in res.values() for s in f["samples"] for ch in s[2:-2])


def test_pii_rejects_invalid_checksums():
    assert not PII.scan_text("card 1234 5678 9012 3456", "x")              # fails Luhn
    assert not any(f["id"] == "data-pii-iban" for f in PII.scan_text("SA0000000000000000000000", "x"))


def test_mcp_config_checks():
    ids = {f["id"] for f in CFG.mcp_servers(APP, [".mcp.json"])}
    assert {"mcp-filesystem-broad", "mcp-shell-server", "mcp-inline-secret", "mcp-remote-http",
            "mcp-unpinned-server", "mcp-unpinned-image"} <= ids
    # the pinned server (@1.4.2) is not flagged unpinned
    fs = CFG.mcp_servers(APP, [".mcp.json"])
    assert not any(f["id"] == "mcp-unpinned-server" and "pinned-search" in f["title"] for f in fs)


def test_notebook_checks():
    ids = {f["id"] for f in CFG.notebooks(APP, ["notebooks/explore.ipynb"])}
    assert {"notebook-secret", "notebook-unsafe-load", "notebook-unpinned-install", "notebook-output-pii"} <= ids


def test_rag_corpus_hidden_instructions():
    ids = {f["id"] for f in CFG.corpora(APP, [{"path": "knowledge/refund-policy.md"},
                                              {"path": "knowledge/shipping.md"}])}
    assert {"rag-hidden-comment-injection", "rag-zero-width"} <= ids


def test_prompt_file_checks():
    ids = {f["id"] for f in CFG.prompts(APP, ["prompts/system.txt"])}
    assert {"prompt-password", "prompt-internal-url", "prompt-backdoor"} <= ids


def test_ai_iac_checks():
    ids = {f["id"] for f in CFG.ai_iac(APP, inv()["ai_iac"])}
    assert {"aiiac-openai-public", "aiiac-openai-no-content-filter", "aiiac-bedrock-no-guardrail",
            "aiiac-sagemaker-internet", "aiiac-vertex-no-cmek"} <= ids


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep not installed")
def test_ai_rule_pack_finds_planted_flaws(tmp_path):
    app = tmp_path / "vulnai"
    shutil.copytree(APP, app)
    env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0")
    p = subprocess.run(["semgrep", "scan", "--metrics=off", "--quiet", "--json", "--config",
                        str(ROOT / "scanner" / "rules" / "ai.yml"), str(app)],
                       capture_output=True, text=True,
                       env=env)
    d = json.loads(p.stdout)
    assert not [e for e in d.get("errors", []) if "Rule" in e.get("message", "")]
    fired = {r["check_id"].split(".")[-1] for r in d["results"]}
    expected = {"sawone-ai-llm-output-to-exec", "sawone-ai-llm-output-to-shell", "sawone-ai-llm-output-to-sql",
                "sawone-ai-llm-output-dangerous-html-js", "sawone-ai-user-input-in-system-prompt",
                "sawone-ai-prompt-logged", "sawone-ai-torch-load-unsafe", "sawone-ai-pickle-model-load",
                "sawone-ai-keras-unsafe-mode", "sawone-ai-trust-remote-code", "sawone-ai-hf-download-unpinned",
                "sawone-ai-faiss-dangerous-deserialization", "sawone-ai-unsafe-yaml-load",
                "sawone-ai-dangerous-agent-tools", "sawone-ai-api-key-in-browser", "sawone-ai-no-max-tokens",
                "sawone-ai-gradio-public-share"}
    assert expected <= fired, expected - fired
    # the pinned from_pretrained in train.py is not a false positive
    unpinned = [r for r in d["results"] if r["check_id"].endswith("hf-download-unpinned")
                and Path(r["path"]).name == "train.py"]
    assert not unpinned
