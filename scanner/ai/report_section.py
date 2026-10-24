"""SawOne-SI's own report chapter: the AI profile of the scanned repository.

Called by the engine's report builder as section(report, R): `report` is the Report instance (its .d is the
report Data, with .reports the report directory and .summary the merged summary), `R` is the report module
(helpers: T, esc, table, kv, note, h1/h2 on the report). Everything is read from files already written by the
scan; this adds a chapter, it never changes a verdict.
"""
import json
import re
from pathlib import Path

RISK_LABELS = {
    "LLM01": "Prompt injection", "LLM02": "Sensitive information disclosure", "LLM03": "Supply chain",
    "LLM04": "Data and model poisoning", "LLM05": "Improper output handling", "LLM06": "Excessive agency",
    "LLM07": "System prompt leakage", "LLM08": "Vector and embedding weaknesses", "LLM09": "Misinformation",
    "LLM10": "Unbounded consumption",
}

# the OWASP LLM risk of each Semgrep AI-pack rule, so SAST findings count in the coverage table (the engine
# carries a finding's CWE but not its OWASP tag; SawOne-SI's own analysers set owasp directly).
RULE_RISK = {
    "llm-output-to-exec": "LLM05", "llm-output-to-shell": "LLM05", "llm-output-to-sql": "LLM05",
    "llm-output-dangerous-html-js": "LLM05", "user-input-in-system-prompt": "LLM01", "prompt-logged": "LLM02",
    "torch-load-unsafe": "LLM03", "pickle-model-load": "LLM03", "keras-unsafe-mode": "LLM03",
    "trust-remote-code": "LLM03", "hf-download-unpinned": "LLM03", "faiss-dangerous-deserialization": "LLM03",
    "unsafe-yaml-load": "LLM03", "dangerous-agent-tools": "LLM06", "langchain-math-rce": "LLM06",
    "api-key-in-browser": "LLM02", "public-key-env-in-client": "LLM02", "no-max-tokens": "LLM10",
    "gradio-public-share": "LLM02",
}


def _risk_of(f):
    risk = f.get("owasp") or ""
    if str(risk).startswith("LLM"):
        return risk
    # Semgrep check_ids are the rule's file path plus the rule name (…rules.sawone-ai-<name>); match the segment
    m = re.search(r"sawone-ai-([a-z0-9-]+)", str(f.get("id") or ""))
    return RULE_RISK.get(m.group(1)) if m else None


def _load(reports, *names):
    for n in names:
        for p in sorted(Path(reports).glob(n)):
            try:
                return json.loads(p.read_text())
            except (OSError, ValueError):
                continue
    return None


def section(report, R):
    d = report.d
    reports = d.reports
    inv = (d.summary.get("inventory") or {}).get("ai") or {}
    ai = _load(reports, "raw/**/ai-inventory.json") or {}
    kinds = ai.get("kinds") or inv.get("kinds") or []
    comps = ai.get("components") or inv.get("components") or []
    if not kinds and not comps:
        return ""   # not an AI project: no chapter
    out = [report.h1("AI security profile", "ai-profile")]
    out.append('<p class="lead">' + R.T("What AI this project uses, the design threats that follow, and how the "
               "findings map to the OWASP LLM Top 10. This profile is built from what the scan detected; the "
               "verdict comes from the stage gates, not from this chapter.") + "</p>")

    # what kind of AI
    kind_label = {"llm-app": "LLM application", "rag": "retrieval (RAG)", "agent": "agent / tools", "mcp": "MCP",
                  "ml-model": "model files", "notebook": "notebooks", "training": "training / fine-tuning",
                  "serving": "model serving", "ai-iac": "AI cloud infrastructure"}
    if kinds:
        pills = " ".join(f'<span class="pill info">{R.esc(R.T(kind_label.get(k, k)))}</span>' for k in kinds)
        out.append(f"<p>{pills}</p>")

    # inventory table
    by_cat = {}
    for c in comps:
        by_cat.setdefault(c["category"], []).append(c["name"])
    cat_label = {"provider": "Model providers", "framework": "Frameworks", "agent": "Agent frameworks",
                 "vector-store": "Vector stores", "ml": "ML libraries", "training": "Training / MLOps",
                 "serving": "Serving", "mcp": "MCP", "guardrail": "Guardrails", "observability": "Observability"}
    rows = [[R.T(cat_label.get(cat, cat)), R.esc(", ".join(sorted(set(names))))]
            for cat, names in sorted(by_cat.items())]
    counts = [("model files", len(ai.get("models") or [])), ("notebooks", len(ai.get("notebooks") or [])),
              ("datasets", len(ai.get("datasets") or [])), ("RAG documents", len(ai.get("corpora") or [])),
              ("prompt files", len(ai.get("prompts") or [])), ("MCP configs", len(ai.get("mcp_configs") or [])),
              ("AI cloud resources", len(ai.get("ai_iac") or []))]
    arts = ", ".join(f"{n} {label}" for label, n in counts if n)
    if arts:
        rows.append([R.T("Artefacts"), R.esc(arts)])
    if rows:
        out.append(R.table(["Component class", "Detected"], rows, "", ["28%", "72%"]))

    # OWASP LLM Top 10 coverage from the findings
    findings = d.merged or []
    by_risk = {}
    for f in findings:
        risk = _risk_of(f)
        if risk:
            by_risk.setdefault(risk, []).append(f)
    out.append(report.h2("OWASP LLM Top 10 coverage", "ai-llm-top10"))
    trows = []
    for i in range(1, 11):
        rk = f"LLM{i:02d}"
        fs = by_risk.get(rk, [])
        block = sum(1 for f in fs if f.get("gating"))
        status = (f'<span class="pill bad">{R.esc(R.T("{n} blocking", n=block))}</span>' if block
                  else f'<span class="pill warn">{R.esc(R.T("{n} tracked", n=len(fs)))}</span>' if fs
                  else f'<span class="pill ok">{R.esc(R.T("none found"))}</span>')
        trows.append([rk, R.T(RISK_LABELS[rk]), status])
    out.append(R.table(["Risk", "Name", "Findings"], trows, "", ["12%", "58%", "30%"]))

    # design threats
    tm = _load(reports, "raw/**/ai-threats.json")
    if tm and tm.get("threats"):
        out.append(report.h2("Design threats", "ai-threats"))
        out.append('<p class="lead">' + R.T("Threats that follow from the architecture the scan detected, each "
                   "mapped to an OWASP LLM risk and a MITRE ATLAS technique. Informational: the scanner stages "
                   "are what evidence and gate these.") + "</p>")
        trows = [[R.sev_pill(t["severity"]), R.esc(t["title"]), f'{t["risk"]} · {R.esc(t.get("atlas", ""))}',
                  R.esc(t["component"])] for t in tm["threats"]]
        out.append(R.table(["Severity", "Threat", "Mapping", "Component"], trows, "", ["12%", "50%", "20%", "18%"]))

    # red-team result, when the stage ran
    rt_rows = [r for r in d.stages if r["stage"] == "ai-redteam"]
    if rt_rows:
        out.append(report.h2("LLM red teaming", "ai-redteam-summary"))
        r = rt_rows[0]
        if r["status"] == "skipped":
            out.append(R.note(R.T("Not run: {why}", why=R.esc(r.get("reason", "")))))
        else:
            out.append(R.note(R.esc(r.get("findings") or R.T("completed"))))
    return "".join(out)
