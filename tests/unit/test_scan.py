"""The whole SawOne-SI scan on the vulnai fixture, through the Sawone engine: stages, phases, findings, report.

Container-based engine scanners (Gitleaks, TruffleHog, Trivy, OSV) are scripted; Semgrep (with the AI rule
pack) and SawOne-SI's own Python analysers run for real. The red-team stage is exercised separately in
test_redteam.py against synthetic tool reports — it is not run against a live endpoint here.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import sawone_si as SI
import sawone_scan as ds

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "tests" / "fixtures" / "vulnai"


class Run:
    """Real subprocess for local tools (semgrep, python); scripted results for `docker run` scanners."""
    def __init__(self, scan):
        self.scan, self.calls = scan, []

    def __call__(self, cmd, log_name=None, timeout=3600, quiet=False, stdout_file=None, env=None):
        self.calls.append(cmd)
        s = " ".join(map(str, cmd))
        out, code = "", 0
        if cmd[0] == "docker":
            if "gitleaks" in s:
                rp = _after(cmd, "--report-path")
                if rp:
                    Path(rp).write_text(json.dumps({"runs": [{"results": []}]}))
                out = "leaks found: 0"
            elif "trivy" in s and "--output" in cmd:
                o = Path(_after(cmd, "--output"))
                o.write_text(json.dumps({"Results": []}) if o.suffix == ".json" else json.dumps({"runs": []}))
            elif "osv" in s and "--output-file" in cmd:
                Path(_after(cmd, "--output-file")).write_text(json.dumps({"runs": []}))
            elif "checkov" in s and "--output-file-path" in cmd:
                d = Path(_after(cmd, "--output-file-path"))
                d.mkdir(parents=True, exist_ok=True)
                (d / "results_sarif.sarif").write_text(json.dumps({"runs": [{"results": []}]}))
            elif "trufflehog" in s and stdout_file:
                Path(stdout_file).write_text("")
            # inspect/pull/network/etc. succeed quietly
        else:
            p = subprocess.run(cmd, cwd=self.scan.ws, capture_output=True, text=True, timeout=timeout,
                               env={**os.environ, **(env or {})})
            out, code = p.stdout + p.stderr, p.returncode
        if log_name:
            (self.scan.reports / "logs" / f"{log_name}.log").write_text(s + "\n\n" + out + f"\n\n[exit code: {code}]\n")
        if stdout_file and cmd[0] != "docker":
            Path(stdout_file).write_text(out)
        return code, out


def _after(cmd, flag):
    cmd = [str(c) for c in cmd]
    return cmd[cmd.index(flag) + 1] if flag in cmd else None


def run_scan(tmp_path):
    ws = tmp_path / "ws"
    shutil.copytree(APP, ws)
    empty = tmp_path / "empty.yml"
    empty.write_text("rules: []\n")
    # the AI rule pack is applied via the profile (semgrep_rules: [rules]); keep registry packs out of the test
    cfg = ds.deep_merge(ds.DEFAULTS, {"semgrep": {"configs": [str(empty)], "framework_filter": False},
                                      "enforce": False, "policy": {"block_kev": False},
                                      "source_sbom": {"enabled": False}})
    s = SI.AIScan(ws, ws / "sawone-si-reports", cfg)
    s.run = Run(s)
    s.docker_ok = True
    s.update_tools = lambda: True
    s.pinned = {t: f"{t}@sha256:0" for t in ("gitleaks", "trufflehog", "trivy", "osv")}
    s.prepare_policy = lambda: None
    s.cleanup = lambda: None
    s.detect()
    return s


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep not installed")
def test_full_scan_reports_every_ai_stage(tmp_path):
    s = run_scan(tmp_path)
    code = s.main()
    rows = {(r["stage"], r["tool"]): r for r in s.stages}
    # AI was detected
    assert set(s.ai["kinds"]) >= {"llm-app", "rag", "agent", "mcp", "ml-model", "notebook", "ai-iac"}
    # each AI stage ran and flagged the planted problems
    assert rows[("ai-prompts", "Prompt checks")]["status"] == "failed"
    assert rows[("ai-notebooks", "Notebook checks")]["status"] == "failed"
    assert rows[("ai-agents", "Agent/MCP checks")]["status"] == "failed"
    assert rows[("ai-models", "Model file scan")]["status"] == "failed"
    assert rows[("ai-data", "Training/RAG data")]["status"] == "failed"
    assert rows[("ai-infra", "AI infrastructure")]["status"] == "failed"
    assert rows[("sast", "Semgrep CE")]["status"] == "failed"              # the AI rule pack fired
    assert rows[("ai-bom", "AI-BOM")]["status"] == "report"
    assert rows[("ai-threat-model", "AI threat model")]["status"] == "report"
    # red team: not configured in the fixture → skipped, not errored
    assert rows[("ai-redteam", "LLM red team")]["status"] == "skipped"
    assert not any(r["status"] == "error" for r in s.stages), [r for r in s.stages if r["status"] == "error"]
    assert code == 0                                                       # report-only mode

    r = s.reports
    summ = json.loads((r / "summary.json").read_text())
    comp = {c["id"]: c for c in summ["compliance"]}
    assert comp["LLM01"]["status"] in ("gap", "evidenced") and comp["LLM01"]["key"] == "owasp-llm"
    assert "SDAIA-PRIV" in comp and "AML.T0051" in comp and "MEASURE-2.7" in comp
    # the AI-BOM is valid CycloneDX with model and data components
    bom = json.loads((r / "raw" / "ai-bom.cdx.json").read_text())
    assert bom["bomFormat"] == "CycloneDX" and any(c["type"] == "machine-learning-model" for c in bom["components"])
    # the model scan caught the dangerous pickle and the safetensors is clean
    models = json.loads((r / "raw" / "ai-models.json").read_text())
    ids = {m["id"] for m in models}
    assert "model-pickle-dangerous-import" in ids and "model-safetensors-ok" in ids
    # PII in the dataset, with Saudi identifiers
    data = json.loads((r / "raw" / "ai-data.json").read_text())
    dids = {d["id"] for d in data}
    assert {"data-pii-sa-national-id", "data-pii-iban"} <= dids
    assert "rag-hidden-comment-injection" in dids
    # reports exist in both languages and carry the AI chapter and brand
    assert (r / "security-report.pdf").exists() and (r / "security-report-ar.pdf").exists()
    html = (r / "security-report.html").read_text()
    assert "SawOne-SI" in html and ">Sawone<" not in html and "AI Application Security" in html
    assert "AI security profile" in html and "OWASP LLM Top 10" in html
    ar = (r / "security-report-ar.html").read_text()
    assert "تقييم" in ar and "نمذجة تهديدات" in ar


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep not installed")
def test_a_non_ai_repo_skips_the_ai_stages(tmp_path):
    ws = tmp_path / "plain"
    (ws).mkdir()
    (ws / "app.py").write_text("def add(a, b):\n    return a + b\n")
    empty = tmp_path / "empty.yml"
    empty.write_text("rules: []\n")
    cfg = ds.deep_merge(ds.DEFAULTS, {"semgrep": {"configs": [str(empty)], "framework_filter": False},
                                      "enforce": False, "policy": {"block_kev": False},
                                      "source_sbom": {"enabled": False}})
    s = SI.AIScan(ws, ws / "sawone-si-reports", cfg)
    s.run = Run(s)
    s.docker_ok = True
    s.update_tools = lambda: True
    s.pinned = {}
    s.prepare_policy = lambda: None
    s.cleanup = lambda: None
    s.detect()
    assert s.ai["kinds"] == []
    s.main()
    for stage in ("ai-models", "ai-data", "ai-infra", "ai-prompts", "ai-redteam", "ai-threat-model"):
        hit = [r for r in s.stages if r["stage"] == stage]
        assert hit and all(h["status"] == "skipped" for h in hit), (stage, hit)
    # no AI chapter when there is no AI
    assert "AI security profile" not in (s.reports / "security-report.html").read_text()


def test_cli_version():
    p = subprocess.run([sys.executable, str(ROOT / "scanner" / "sawone_si.py"), "--version"],
                       capture_output=True, text=True, env=os.environ)
    assert p.stdout.startswith("SawOne-SI 1.0.0")
