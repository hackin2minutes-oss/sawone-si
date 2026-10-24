# Changelog

## 1.0.0 — first release

DevSecOps for AI / LLM applications on the Sawone engine (v1.4.0), by DevSecOps phase.

- **Detection:** which kinds of AI a repo contains — LLM app, RAG, agent/tools, MCP, model files, notebooks,
  training, serving, AI cloud infrastructure — across Python, JS/TS, Java, C# and Go, from code and manifests.
- **Code:** Semgrep with the SawOne-SI AI rule pack (19 rules: LLM output to exec/shell/SQL/HTML, user input in
  the system prompt, unsafe model loading, `trust_remote_code`, unpinned HF downloads, dangerous agent tools,
  provider keys in the browser, missing `max_tokens`, Gradio public share); prompt, notebook and agent/MCP
  configuration checks.
- **Build:** a CycloneDX ML-BOM; model-file scanning that examines pickle/PyTorch/NumPy/Keras/GGUF/safetensors
  as data and never loads them; training and RAG data checks (PII incl. Saudi national IDs/IBANs with
  checksums, and hidden-instruction poisoning); AI cloud-infrastructure checks (Azure OpenAI/ML, Bedrock,
  SageMaker, Vertex AI).
- **Test:** opt-in LLM red teaming — a thin adapter that drives garak and promptfoo against an endpoint you own,
  with a gating policy (injection/leakage/insecure-output/excessive-agency block; jailbreak/toxicity track) and
  API-key redaction of every artifact.
- **Operate:** guardrail and abuse-control presence (guardrails, moderation, rate/token limits, observability).
- An automatic AI threat model (STRIDE + OWASP LLM / MITRE ATLAS) from the detected architecture.
- Compliance maps: OWASP LLM Top 10 (2025), OWASP ML Top 10, MITRE ATLAS, NIST AI RMF (incl. GenAI profile
  AI 600-1), ISO/IEC 42001 and SDAIA AI Ethics, alongside the engine's NCA ECC / SAMA / PDPL maps; a dedicated
  AI security-profile chapter in the EN/AR PDF.
- Reusable phase-wise workflow (parallel gate matrix + opt-in red-team job), single-step action, two signed
  images (scanner built on a signature-verified Sawone release; garak + promptfoo red-team runner).
- Engine change (Sawone v1.4.0): a product profile can add its own report chapter via `report_sections`.
