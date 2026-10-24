"""An automatic AI threat model from the detected inventory.

Not a replacement for pytm/Threagile (the engine still runs those on a hand-written model): this names the
design-level AI threats that follow from what the scan found — an LLM that takes user input, a RAG corpus, an
agent with tools, model files, training data — and maps each to the OWASP LLM Top 10 (2025) and MITRE ATLAS.
These threats are informational in the report: the scanners are what gate.
"""


def build(ai):
    """Return (model, threats). model: {nodes, edges} for a simple data-flow view. threats: list of dicts
    (id, title, severity, risk, atlas, component)."""
    kinds = set(ai.get("kinds") or [])
    cats = {c["category"] for c in ai.get("components", [])}
    nodes, edges, threats = [], [], []

    def node(nid, label, kind):
        nodes.append({"id": nid, "label": label, "kind": kind})

    def edge(a, b, label=""):
        edges.append({"from": a, "to": b, "label": label})

    def threat(tid, title, severity, risk, atlas, component):
        threats.append({"id": tid, "title": title, "severity": severity, "risk": risk, "atlas": atlas,
                        "component": component})

    node("user", "User / caller", "actor")
    has_llm = "llm-app" in kinds or cats & {"provider", "framework", "agent"}
    if has_llm:
        node("llm", "Language model", "model")
        edge("user", "llm", "prompt")
        edge("llm", "user", "response")
        threat("AITM-INJECT", "Untrusted input reaches the model: a user can override its instructions "
               "(prompt injection)", "HIGH", "LLM01", "AML.T0051", "Language model")
        threat("AITM-OUTPUT", "Model output is consumed downstream: if it is rendered, executed or queried "
               "without handling, it is an injection sink", "HIGH", "LLM05", "AML.T0049", "Language model")
        threat("AITM-DOS", "Unbounded generation: a caller can drive long, costly completions "
               "(denial of wallet)", "MEDIUM", "LLM10", "AML.T0034", "Language model")
    if "rag" in kinds or cats & {"vector-store"}:
        node("vs", "Vector store / retrieval", "datastore")
        node("docs", "Knowledge documents", "data")
        edge("docs", "vs", "embed")
        edge("vs", "llm", "retrieved context")
        threat("AITM-RAG-POISON", "Retrieved documents are fed to the model as context: a poisoned or "
               "attacker-controlled document is indirect prompt injection", "HIGH", "LLM08", "AML.T0051",
               "Vector store / retrieval")
    if "agent" in kinds or cats & {"agent"} or "mcp" in kinds:
        node("tools", "Tools / MCP servers", "process")
        edge("llm", "tools", "tool calls")
        edge("tools", "llm", "tool results")
        threat("AITM-AGENCY", "The model can invoke tools: injection or a bad decision becomes real-world "
               "action (excessive agency)", "HIGH", "LLM06", "AML.T0053", "Tools / MCP servers")
    if ai.get("models"):
        node("models", "Model files", "artifact")
        edge("models", "llm", "load")
        threat("AITM-SUPPLY", "Model files are loaded at runtime: an unsafe format (pickle, Lambda layer) or an "
               "untrusted source runs code", "HIGH", "LLM03", "AML.T0010", "Model files")
    if "training" in kinds or ai.get("datasets"):
        node("train", "Training / fine-tuning data", "data")
        edge("train", "models", "train")
        threat("AITM-DATA-POISON", "Training or fine-tuning data shapes the model: poisoned or sensitive data is "
               "learned", "MEDIUM", "LLM04", "AML.T0020", "Training / fine-tuning data")
        threat("AITM-PRIVACY", "Personal data in training sets can be memorised and later disclosed", "HIGH",
               "LLM02", "AML.T0057", "Training / fine-tuning data")
    if ai.get("ai_iac") or "serving" in kinds:
        node("infra", "Model endpoint / cloud service", "infrastructure")
        edge("llm", "infra", "hosted on")
        threat("AITM-INFRA", "The model endpoint's exposure, authentication and logging decide who can reach it "
               "and whether abuse is seen", "MEDIUM", "LLM10", "AML.T0024", "Model endpoint / cloud service")
    return {"nodes": nodes, "edges": edges}, threats
