#!/usr/bin/env python3
"""SawOne-SI: DevSecOps for AI / LLM applications, on the Sawone engine.

Stages, by DevSecOps phase:
  plan     threat-model     OWASP pytm / Threagile (Sawone)
           ai-threat-model  an automatic AI threat model (STRIDE + OWASP LLM / ATLAS) of what was detected
  code     secrets          Gitleaks, TruffleHog (Sawone)
           sast             Semgrep with the SawOne-SI AI rule pack + language packs (Sawone)
           ai-prompts       prompt / system-prompt files: secrets, internal URLs, backdoor phrases
           ai-notebooks     Jupyter notebooks: secrets, personal data in outputs, unsafe loading, unpinned installs
           ai-agents        agent and MCP configuration: code/shell tools, broad filesystem, unpinned servers
  build    sca              dependencies (Sawone)
           ai-bom           CycloneDX ML-BOM of models, providers, frameworks, datasets and prompts
           ai-models        model files examined as data (never loaded): pickle/torch/numpy/keras/gguf
           ai-data          training and RAG data: personal data (PDPL) and hidden-instruction poisoning
           iac, cicd        Sawone (when the repo has IaC or workflows)
           ai-infra         AI cloud services in IaC: public access, key auth, no content filter / guardrail
  test     container, dast  the built app (Sawone), when there is one
           ai-redteam       garak + promptfoo against an endpoint you configure (opt-in)
  release  policy           risk policy and the gate decision (Sawone)
  operate  runtime          WAF (Sawone), when there is a running app
           ai-guardrails    runtime safeguards present: guardrails, moderation, rate/token limits, observability
  monitor  tracking         DefectDojo (Sawone)

The engine (report, phases, threat model, risk policy, merge, Arabic PDF) is Sawone's: SAWONE_ENGINE points to
its scanner directory (/opt/sawone in the image).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = Path(os.environ.get("SAWONE_ENGINE") or "/opt/sawone")
os.environ.setdefault("SAWONE_PROFILE", str(HERE / "profile.yml"))   # before the engine is imported
sys.path[:0] = [str(HERE), str(ENGINE)]

import findings as F  # noqa: E402
import sawone_scan as ds  # noqa: E402
from ai import configs as CFG  # noqa: E402
from ai import detect as DET  # noqa: E402
from ai import modelscan as MS  # noqa: E402
from ai import pii as PII  # noqa: E402
from ai import redteam as RT  # noqa: E402
from ai import supply_chain as SC  # noqa: E402
from ai import threatmodel as AITM  # noqa: E402
from ai import pr_review as PR  # noqa: E402

log = ds.log
VERSION = "1.0.0"
REDTEAM_IMAGE = os.environ.get("SAWONE_SI_REDTEAM_IMAGE", "ghcr.io/hackin2minutes-oss/sawone-si-redteam:1")
SEV_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

ds.DEFAULTS.setdefault("ai", {
    "redteam": {"endpoint": "", "target": "", "api": "openai", "model": "", "profile": "quick",
                "garak": True, "promptfoo": {"enabled": True, "generate": False},
                "max_minutes": 20, "image": REDTEAM_IMAGE},
    "guardrails": {"required": []},     # guardrail component names a reviewer expects (empty = report only)
    "max_data_files": 300,
})


def to_sarif(tool, results, path, info_uri="https://github.com/hackin2minutes-oss/sawone-si"):
    """Minimal SARIF 2.1.0 for SawOne-SI's own analysers."""
    rules, out = {}, []
    for f in results:
        rid = f["id"]
        rules.setdefault(rid, {"id": rid, "shortDescription": {"text": f["title"][:120]},
                               "properties": {"tags": [t for t in (f.get("cwe"), f.get("owasp"), f.get("risk")) if t],
                                              "security-severity": {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5",
                                                                    "LOW": "3.0", "INFO": "1.0"}[f["severity"]]}})
        loc = {"physicalLocation": {"artifactLocation": {"uri": str(f.get("file") or "ai").split(" (")[0]}}}
        if f.get("line"):
            loc["physicalLocation"]["region"] = {"startLine": int(f["line"])}
        out.append({"ruleId": rid, "level": SEV_LEVEL[f["severity"]], "message": {"text": f["title"]},
                    "locations": [loc]})
    Path(path).write_text(json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool, "version": VERSION, "informationUri": info_uri,
                                      "rules": list(rules.values())}}, "results": out}]}, indent=1))


class AIScan(ds.Scan):
    """The Sawone scan with AI/LLM stages. The AI inventory (self.ai) is built once in detect()."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.ai = {}
        rt = self.cfg.setdefault("ai", dict(ds.DEFAULTS["ai"]))["redteam"]
        if os.environ.get("SAWONE_LLM_ENDPOINT"):
            rt["endpoint"] = os.environ["SAWONE_LLM_ENDPOINT"]
        if os.environ.get("SCAN_REDTEAM_PROFILE"):
            rt["profile"] = os.environ["SCAN_REDTEAM_PROFILE"]

    # ---------------------------------------------------------------- detection
    def detect(self):
        super().detect()
        self.ai = DET.detect(self.ws, exclude=set(ds.ALWAYS_EXCLUDE) | {self.reports.name},
                             extra_skip=self.cfg.get("exclude", []), manifests=self.inv["manifests"])
        for m in self.ai["models"]:
            m["abs"] = str((self.ws / m["path"]))
        self.inv["ai"] = {k: self.ai[k] for k in ("kinds", "components", "models", "notebooks", "datasets",
                                                  "corpora", "prompts", "mcp_configs", "ai_iac", "ai_images")}
        (self.reports / "raw" / "ai-inventory.json").write_text(json.dumps(self.ai, indent=1, default=str))
        log("ai: " + DET.summary_line(self.ai))
        return self.inv

    def needed_tools(self):
        # AI stages add no sibling scanner images; Semgrep (AI rule pack) is already a pip tool
        return super().needed_tools()

    def steps(self):
        return [("threat-model", self.scan_threat_model), ("ai-threat-model", self.scan_ai_threat_model),
                ("secrets", self.scan_secrets), ("sast", self.scan_sast), ("ai-prompts", self.scan_ai_prompts),
                ("ai-notebooks", self.scan_ai_notebooks), ("ai-agents", self.scan_ai_agents),
                ("ai-supply-chain", self.scan_ai_supply_chain),
                ("sca", self.scan_sca), ("ai-bom", self.scan_ai_bom), ("ai-models", self.scan_ai_models),
                ("ai-data", self.scan_ai_data), ("iac", self.scan_iac), ("ai-infra", self.scan_ai_infra),
                ("cicd", self.scan_cicd), ("container", self.scan_containers), ("dast", self.scan_dast),
                ("ai-redteam", self.scan_ai_redteam), ("runtime", self.scan_waf),
                ("ai-guardrails", self.scan_ai_guardrails), ("tracking", self.defectdojo),
                ("pr-review", self.scan_pr_review)]

    # ---------------------------------------------------------------- helpers
    def _items(self, stage, tool, results, kind="ai"):
        out = []
        for f in results:
            path = str(f.get("file") or "")
            it = F.issue(stage, tool, kind, f["id"], path.split(" (")[0] or None, f.get("line"),
                         f["severity"], f["title"], ws=self.ws if path and f.get("line") else None,
                         gating=f.get("gating", f["severity"] in self.sev and f["severity"] != "INFO"),
                         key=f.get("detail") or f.get("component") or path or f["id"])
            if f.get("cwe"):
                it["cwe"] = [f["cwe"].split(":")[0]] if isinstance(f["cwe"], str) else f["cwe"]
            if f.get("owasp") or f.get("risk"):
                it["owasp"] = f.get("owasp") or f.get("risk")
            out.append(it)
        return out

    def _record_sarif(self, stage, tool, results, slug, label, extra_note=""):
        sarif = self.reports / "sarif" / f"ai-{slug}.sarif"
        to_sarif(f"SawOne-SI {label}", results, sarif)
        self.sarif_tag(sarif, slug)
        blocking = sum(1 for f in results if f.get("gating", f["severity"] in self.sev and f["severity"] != "INFO"))
        self.gate(stage, label, blocking, f"{len(results)} finding(s)" + (f" · {extra_note}" if extra_note else ""),
                  items=self._items(stage, label, results))

    # ---------------------------------------------------------------- plan: AI threat model
    def scan_ai_threat_model(self):
        if not self.ai.get("ai"):
            return self.record("ai-threat-model", "AI threat model", "skipped", "no AI components detected", gate=False)
        model, threats = AITM.build(self.ai)
        (self.reports / "raw" / "ai-threats.json").write_text(json.dumps({"model": model, "threats": threats}, indent=1))
        open_items = [t for t in threats if t["severity"] in ("HIGH", "CRITICAL")]
        items = [F.issue("ai-threat-model", "AI threat model", "threat", t["id"], "AI system", None, t["severity"],
                         f'{t["title"]} [{t["risk"]}]', key=t["id"],
                         gating=False) for t in threats]      # design threats inform, scanners gate
        for it, t in zip(items, threats):
            it["owasp"] = t["risk"]
            it["location"] = t["component"]
        self.gate("ai-threat-model", "AI threat model", 0,
                  f"{len(threats)} design threat(s) across {len(model['nodes'])} component(s); "
                  f"{len(open_items)} high/critical (informational)", report_only=True, items=items)

    # ---------------------------------------------------------------- code: prompts, notebooks, agents/MCP
    def scan_ai_prompts(self):
        if not self.ai["prompts"]:
            return self.record("ai-prompts", "Prompt checks", "skipped", "no prompt files found", gate=False)
        res = CFG.prompts(self.ws, self.ai["prompts"])
        self._record_sarif("ai-prompts", "Prompt checks", res, "prompts", "Prompt checks",
                           f"{len(self.ai['prompts'])} prompt file(s)")

    def scan_ai_notebooks(self):
        if not self.ai["notebooks"]:
            return self.record("ai-notebooks", "Notebook checks", "skipped", "no notebooks found", gate=False)
        res = CFG.notebooks(self.ws, self.ai["notebooks"])
        self._record_sarif("ai-notebooks", "Notebook checks", res, "notebooks", "Notebook checks",
                           f"{len(self.ai['notebooks'])} notebook(s)")

    def scan_ai_agents(self):
        cfgs = self.ai["mcp_configs"]
        agent_comp = [c for c in self.ai["components"] if c["category"] in ("agent", "mcp")]
        if not cfgs and not agent_comp:
            return self.record("ai-agents", "Agent/MCP checks", "skipped", "no MCP configs or agent frameworks found",
                               gate=False)
        res = CFG.mcp_servers(self.ws, cfgs)
        note = f"{len(cfgs)} MCP config(s)"
        if agent_comp and not cfgs:
            note = ", ".join(c["name"] for c in agent_comp[:4]) + " (agent framework in code — see SAST)"
        self._record_sarif("ai-agents", "Agent/MCP checks", res, "agents", "Agent/MCP checks", note)

    # ---------------------------------------------------------------- code: LLM supply-chain
    def scan_ai_supply_chain(self):
        """Static supply-chain checks: trust_remote_code, unverified model sources,
        unsigned downloads, VCS installs, unpinned AI deps, missing model provenance."""
        res = SC.scan(self.ws, self.ai)
        (self.reports / "raw" / "ai-supply-chain.json").write_text(json.dumps(res, indent=1))
        if not res:
            return self.record("ai-supply-chain", "LLM supply-chain", "passed",
                               "no supply-chain issues found", gate=False)
        self._record_sarif("ai-supply-chain", "LLM supply-chain", res, "supply-chain",
                           "LLM supply-chain",
                           f"{len(res)} finding(s): model integrity, pinning, provenance")

    # ---------------------------------------------------------------- build: AI-BOM, models, data, infra
    def scan_ai_bom(self):
        if not self.ai.get("ai"):
            return self.record("ai-bom", "AI-BOM", "skipped", "no AI components detected", gate=False)
        bom = ai_bom(self.ai)
        (self.reports / "raw" / "ai-bom.cdx.json").write_text(json.dumps(bom, indent=1))
        n_models, n_comp = len(self.ai["models"]), len(self.ai["components"])
        unpinned = [m for m in self.ai["models"] if m["format"] in ("pickle", "pytorch", "joblib", "numpy")]
        self.gate("ai-bom", "AI-BOM", 0,
                  f"{n_comp} AI component(s), {n_models} model file(s), {len(self.ai['datasets'])} dataset(s) "
                  f"(CycloneDX ML-BOM, raw/ai-bom.cdx.json)" + (f" · {len(unpinned)} code-bearing model format(s)"
                                                               if unpinned else ""), report_only=True)

    def scan_ai_models(self):
        if not self.ai["models"]:
            return self.record("ai-models", "Model file scan", "skipped", "no model files found", gate=False)
        res = MS.scan_models(self.ai["models"])
        (self.reports / "raw" / "ai-models.json").write_text(json.dumps(res, indent=1))
        crit = sum(1 for f in res if f["severity"] in ("CRITICAL", "HIGH"))
        self._record_sarif("ai-models", "Model file scan", res, "models", "Model file scan",
                           f"{len(self.ai['models'])} model file(s), {crit} that would run code on load")

    def scan_ai_data(self):
        entries = (self.ai["datasets"] + self.ai["corpora"])[: self.cfg["ai"].get("max_data_files", 300)]
        if not entries:
            return self.record("ai-data", "Training/RAG data", "skipped", "no datasets or RAG documents found",
                               gate=False)
        pii = PII.scan_files(self.ws, entries, max_files=self.cfg["ai"].get("max_data_files", 300))
        poison = CFG.corpora(self.ws, self.ai["corpora"])
        res = pii + poison
        (self.reports / "raw" / "ai-data.json").write_text(json.dumps(res, indent=1, default=str))
        kinds = sorted({f.get("kind", "") for f in pii if f.get("kind")})
        self._record_sarif("ai-data", "Training/RAG data", res, "data", "Training/RAG data",
                           f"{len(entries)} file(s)" + (f" · PII: {', '.join(kinds)}" if kinds else "")
                           + (f" · {len(poison)} poisoning/injection signal(s)" if poison else ""))

    def scan_ai_infra(self):
        if not self.ai["ai_iac"]:
            return self.record("ai-infra", "AI infrastructure", "skipped", "no AI cloud resources in IaC", gate=False)
        res = CFG.ai_iac(self.ws, self.ai["ai_iac"])
        self._record_sarif("ai-infra", "AI infrastructure", res, "infra", "AI infrastructure",
                           f"{len(self.ai['ai_iac'])} AI cloud resource(s)")

    # ---------------------------------------------------------------- test: red team (opt-in)
    def scan_ai_redteam(self):
        rt = self.cfg["ai"]["redteam"]
        if not self.ai.get("ai") and not rt.get("endpoint"):
            return self.record("ai-redteam", "LLM red team", "skipped", "no AI components detected", gate=False)
        if not RT.configured(self.cfg):
            return self.record("ai-redteam", "LLM red team", "skipped",
                               "not configured: set ai.redteam.endpoint (a test endpoint you own) and an API key "
                               "env var to attack a live model — see the README", gate=False)
        try:
            findings = self._run_redteam(rt)
        except Exception as e:  # noqa: BLE001 — a red-team tool crash must not take the scan down
            return self.record("ai-redteam", "LLM red team", "error", f"{type(e).__name__}: {e}")
        if findings is None:
            return
        res = [{"id": f["id"], "severity": f["severity"], "title": f["title"], "file": "redteam endpoint",
                "gating": f["gating"], "owasp": f["risk"], "detail": f.get("detail")} for f in findings]
        self._record_sarif("ai-redteam", "LLM red team", res, "redteam", "LLM red team", RT.summarise(findings))

    def _run_redteam(self, rt):
        """Drive garak and promptfoo in the red-team container against the configured endpoint. The API key is
        passed only through the container environment. Returns parsed findings, or records an error / skip."""
        out = self.reports / "raw" / "redteam"
        out.mkdir(parents=True, exist_ok=True)
        os.chmod(out, 0o777)
        image = rt.get("image") or REDTEAM_IMAGE
        if self.run(["docker", "image", "inspect", image], quiet=True)[0] != 0:
            if self.run(["docker", "pull", "-q", image], log_name="redteam-pull", timeout=1800)[0] != 0:
                self.record("ai-redteam", "LLM red team", "error",
                            f"the red-team image could not be pulled ({image}): {self.last_error('redteam-pull')}")
                return None
        endpoint = rt["endpoint"]
        key_env = next((k for k in ("SAWONE_LLM_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "LLM_API_KEY")
                        if os.environ.get(k)), None)
        env = {"SAWONE_LLM_ENDPOINT": endpoint, "SAWONE_LLM_MODEL": rt.get("model", ""),
               "SAWONE_LLM_API": rt.get("api", "openai"), "SAWONE_REDTEAM_PROFILE": rt.get("profile", "quick"),
               "PROMPTFOO_DISABLE_TELEMETRY": "1", "PROMPTFOO_DISABLE_REMOTE_GENERATION":
               "0" if rt.get("promptfoo", {}).get("generate") else "1",
               "SAWONE_REDTEAM_GARAK": "1" if rt.get("garak", True) else "0",
               "SAWONE_REDTEAM_PROMPTFOO": "1" if rt.get("promptfoo", {}).get("enabled", True) else "0"}
        if key_env:
            env["SAWONE_LLM_API_KEY"] = os.environ[key_env]
        mins = int(rt.get("max_minutes", 20))
        # the image's entrypoint runs garak and/or promptfoo and writes reports into /out
        code, _ = self.docker("_redteam", ["--out", "/out"], "redteam",
                              extra=["-v", f"{out}:/out", "--net=host", "--add-host=host.docker.internal:host-gateway",
                                     *sum([["-e", k] for k in env], [])],
                              timeout=60 * (mins + 10), mount=False)
        # docker() looks up IMAGES[tool]; register the image under a private key
        if code not in (0, 1):
            self.record("ai-redteam", "LLM red team", "error", self.last_error("redteam"))
            return None
        findings = []
        for rep in sorted(out.glob("*.report.jsonl")):
            findings += RT.parse_garak(rep)
        for rep in sorted(out.glob("promptfoo*.json")):
            findings += RT.parse_promptfoo(rep)
        return findings

    # ---------------------------------------------------------------- operate: guardrails present
    def scan_ai_guardrails(self):
        if not self.ai.get("ai"):
            return self.record("ai-guardrails", "Guardrails", "skipped", "no AI components detected", gate=False)
        present = sorted({c["name"] for c in self.ai["components"] if c["category"] in ("guardrail", "observability")})
        res = []
        if not present:
            res.append({"id": "ai-no-guardrails", "severity": "MEDIUM", "file": "AI system",
                        "title": "No input/output guardrail, moderation or content-safety library was detected: "
                                 "prompt injection and unsafe output reach users unchecked",
                        "owasp": "LLM05", "gating": False})
        required = self.cfg["ai"]["guardrails"].get("required") or []
        missing = [r for r in required if not any(r.lower() in c.lower() for c in present)]
        for r in missing:
            res.append({"id": "ai-guardrail-missing", "severity": "HIGH", "file": "AI system",
                        "title": f"required guardrail '{r}' is not present in the code", "gating": True})
        (self.reports / "raw" / "ai-guardrails.json").write_text(json.dumps(
            {"present": present, "required": required, "missing": missing}, indent=1))
        items = self._items("ai-guardrails", "Guardrails", res)
        if not missing:
            # nothing required is missing: an informational row (no false "passed" when none are present)
            label = "present: " + ", ".join(present) if present else ("no guardrail, moderation or "
                    "content-safety library detected — prompt injection and unsafe output are unchecked")
            return self.gate("ai-guardrails", "Guardrails", 0, label, report_only=True, items=items)
        self.gate("ai-guardrails", "Guardrails", sum(1 for f in res if f.get("gating")),
                  ("present: " + ", ".join(present) + " · " if present else "")
                  + f"{len(missing)} required guardrail(s) missing", items=items)

    # ---------------------------------------------------------------- monitor: GitHub PR review annotations
    def scan_pr_review(self):
        """Post inline SARIF findings as GitHub PR review comments and Actions annotations.

        This stage is a no-op when GITHUB_TOKEN or a PR context is absent.
        It also emits ::error / ::warning annotation lines for every SARIF file
        found in reports/sarif/, which GitHub Actions surfaces in the Files tab.
        """
        sarif_dir = self.reports / "sarif"
        # Always emit workflow annotations (works in push + PR workflows)
        if sarif_dir.is_dir():
            for sf in sorted(sarif_dir.glob("*.sarif")):
                PR.annotate_from_sarif(sf, log=log)
        # PR-specific inline review
        posted = PR.post_pr_review(self.reports, log=log)
        status = "posted" if posted else "skipped"
        detail = "inline review comments posted to PR" if posted else \
                 "not a PR context or GITHUB_TOKEN absent (annotations still emitted above)"
        self.record("pr-review", "PR review annotations", status, detail, gate=False)


# CycloneDX 1.6 ML-BOM ------------------------------------------------------
def ai_bom(ai):
    comps = []
    for c in ai["components"]:
        comps.append({"type": "library" if c["category"] in ("framework", "provider", "agent", "vector-store")
                      else "application", "name": c["name"], "group": c["category"],
                      "evidence": {"occurrences": [{"location": e} for e in c.get("evidence", [])[:5]]}})
    for m in ai["models"]:
        comps.append({"type": "machine-learning-model", "name": Path(m["path"]).name,
                      "properties": [{"name": "sawone:format", "value": m["format"]},
                                     {"name": "sawone:path", "value": m["path"]},
                                     {"name": "sawone:size", "value": str(m.get("size", ""))}]})
    for d in ai["datasets"] + ai["corpora"]:
        comps.append({"type": "data", "name": d["path"],
                      "properties": [{"name": "sawone:kind", "value": "dataset"}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"tools": [{"name": "SawOne-SI", "version": VERSION}], "properties":
                         [{"name": "sawone:ai-kinds", "value": ",".join(ai["kinds"])}]},
            "components": comps}


# register the red-team image so Scan.docker() can find it under the "_redteam" tool key
ds.IMAGES["_redteam"] = REDTEAM_IMAGE

_orig_resolve_lock = ds.resolve_lock


def _resolve_lock_wrapper(out_path):
    # Only lock _redteam if it is resolvable on the registry; before the first release,
    # the companion image has not been pushed yet and must not block the scanner lock.
    redteam = ds.IMAGES.pop("_redteam", None)
    if redteam:
        try:
            p = subprocess.run(["docker", "buildx", "imagetools", "inspect", redteam, "--format", "{{json .Manifest}}"],
                               capture_output=True, text=True, timeout=30)
            if p.returncode == 0 and "sha256:" in p.stdout:
                ds.IMAGES["_redteam"] = redteam
        except Exception:
            pass
    try:
        return _orig_resolve_lock(out_path)
    finally:
        if redteam:
            ds.IMAGES["_redteam"] = redteam


ds.resolve_lock = _resolve_lock_wrapper


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(f"SawOne-SI {VERSION} (Sawone engine at {ENGINE})")
        return 0
    return ds.main(AIScan, "SawOne-SI: DevSecOps for AI / LLM applications")


if __name__ == "__main__":
    sys.exit(main())
