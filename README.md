# SawOne-SI

**DevSecOps for AI / LLM applications, by phase.** SawOne-SI scans an AI project — its code, prompts,
notebooks, agent and MCP configuration, model files, training and retrieval data, and AI cloud infrastructure —
and, when you point it at a test endpoint you own, red-teams the live model. It reports in the same enterprise
PDF (English and Arabic), SARIF, JUnit and evidence pack as
[Sawone](https://github.com/hackin2minutes-oss/sawone), whose engine it runs on, and maps results to the
**OWASP LLM Top 10 (2025)**, **OWASP ML Top 10**, **MITRE ATLAS**, **NIST AI RMF**, **ISO/IEC 42001** and the
**SDAIA AI Ethics Principles**.

```yaml
jobs:
  sawone-si:
    permissions: { contents: read, actions: read, security-events: write }
    uses: hackin2minutes-oss/sawone-si/.github/workflows/sawone-si-scan.yml@<commit-sha> # v1.0.0
    with:
      redteam-endpoint: https://staging-assistant.example/v1/chat/completions   # optional, a test endpoint you own
    secrets:
      redteam-api-key: ${{ secrets.STAGING_LLM_KEY }}
```

"AI" means several different things, and each needs different checks. SawOne-SI detects which ones a repository
contains — an LLM application, retrieval (RAG), an agent with tools, MCP, model files, notebooks, training,
serving, AI cloud infrastructure — and runs only the stages that apply.

## What it checks, by DevSecOps phase

| Phase | Stage | Finds |
|---|---|---|
| **Plan** | threat-model (Sawone) + **AI threat model** | design threats from the detected architecture, mapped to OWASP LLM and MITRE ATLAS |
| **Code** | secrets (Sawone) | keys and passwords in code and history |
| | sast (Semgrep + **AI rule pack**) | LLM output reaching `exec`/shell/SQL/HTML, user input in the system prompt, `torch.load`/pickle/`trust_remote_code`, unpinned Hugging Face downloads, dangerous agent tools, provider keys in the browser, missing `max_tokens` |
| | **prompts** | secrets, internal endpoints and override/backdoor phrases in prompt and system-prompt files |
| | **notebooks** | secrets in cells, personal data or tokens in saved outputs, unsafe loading, unpinned installs |
| | **agents / MCP** | tools that run code or shell, filesystem servers rooted too broadly, unpinned MCP servers, inline tokens, plain-HTTP remote servers |
| **Build** | sca (Sawone) | known vulnerabilities in dependencies |
| | **AI-BOM** | a CycloneDX ML-BOM of models, providers, frameworks, vector stores, datasets and prompts |
| | **model files** | pickles and PyTorch checkpoints that would run code, NumPy object arrays, Keras Lambda layers, GGUF chat-template escapes — **examined as data, never loaded** — against safe formats (safetensors, ONNX) |
| | **training / RAG data** | personal data (Saudi national IDs, IBANs, cards, contacts — PDPL and disclosure risk) and documents carrying instructions hidden from a reader (indirect prompt injection, poisoning) |
| | iac, cicd (Sawone) | when the repo has infrastructure code or workflows |
| | **AI infrastructure** | Azure OpenAI/ML, Bedrock, SageMaker, Vertex AI in IaC: public access, key-only auth, missing content filters and guardrails, missing encryption/logging |
| **Test** | container, dast (Sawone) | the built app, when there is one |
| | **LLM red teaming** | a live attack on the endpoint you configure, run with **garak** and **promptfoo**: prompt injection, system-prompt and data leakage, insecure output, excessive agency, jailbreaks (opt-in) |
| **Release** | policy + gate (Sawone) | the risk policy and the gate decision |
| **Operate** | runtime (Sawone) + **guardrails** | whether the app has guardrails, moderation, rate/token limits and prompt observability |
| **Monitor** | tracking (Sawone) | DefectDojo |

## LLM red teaming (opt-in)

The red-team stage does **not** ship its own attack payloads or a target to attack. It drives two established
open-source red-team tools — [garak](https://github.com/NVIDIA/garak) and
[promptfoo](https://github.com/promptfoo/promptfoo), which carry their own probe sets — against an endpoint you
name and own, and turns their reports into findings. It runs only when you set `redteam-endpoint`; with no
endpoint it reports *not configured* and the matching controls are *not assessed*, never passed.

- **Point it at a test or staging deployment, never production.** The attacks ask the model to call tools, leak
  data and ignore its instructions; a vulnerable application may act on that.
- The API key travels only in the request header (as a secret), and the runner **redacts it from every file**
  it leaves behind — configs, tool reports and logs.
- promptfoo's cloud attack generation is off by default (`PROMPTFOO_DISABLE_REMOTE_GENERATION`).
- Gating: successful **prompt injection, data/system-prompt leakage, insecure output, excessive agency** (HIGH)
  block the pipeline; jailbreak and toxicity results are tracked, not blocking.

Configure it in `.sawone.yml`:

```yaml
ai:
  redteam:
    endpoint: https://staging-assistant.example/v1/chat/completions
    api: openai            # openai | rest | anthropic | ollama
    model: gpt-4o
    profile: quick         # quick (fast probe subset) | full
  guardrails:
    required: [guardrails-ai]   # optional: fail if a named guardrail library is absent
```

## Using it

**Reusable workflow** (recommended: parallel gate jobs per stage, previous-report trend, merged report):

| Input | Default | |
|---|---|---|
| `path` | `.` | the project directory |
| `phases` | `all` | `plan,code,build` for a fast PR check |
| `redteam-endpoint` | | a test LLM endpoint you own; empty skips the live red team |
| `redteam-profile` | `quick` | `quick` or `full` probe depth |
| `enforce` / `gate-severity` | `true` / `HIGH,CRITICAL` | |
| `pr-gate` | `new` | pull requests fail only on findings they introduce |
| `baseline-file` | `.sawone-baseline.yml` | accepted risks and threat decisions (owner, expiry) |
| `block-kev` / `epss-threshold` | `true` / `0` | |
| `report-languages` | `en,ar` | |
| `upload-sarif` | `auto` | code scanning on public repositories |
| `scanner-image` | `ghcr.io/hackin2minutes-oss/sawone-si-scanner:1` | its Sigstore signature is verified before use |

Pass the endpoint's key as the `redteam-api-key` **secret** (never an input).

**Single-step action**:

```yaml
- uses: hackin2minutes-oss/sawone-si@<commit-sha> # v1.0.0
  with:
    redteam-endpoint: https://staging-assistant.example/v1/chat/completions
  env:
    SAWONE_LLM_API_KEY: ${{ secrets.STAGING_LLM_KEY }}
```

## Results

The `sawone-si-report` artifact: `security-report.pdf` / `security-report-ar.pdf` (branded SawOne-SI, with the
DevSecOps lifecycle, every stage by phase, the **AI security profile** chapter — component inventory, OWASP LLM
Top 10 coverage, design threats with ATLAS mapping, red-team summary — and the compliance maps), `summary.md`,
`findings.json`, `sarif/` (code scanning), `junit.xml`, `evidence/` (signed on release-branch runs),
`raw/ai-bom.cdx.json`, `raw/ai-models.json`, `raw/ai-data.json` and, when the red team ran, `raw/redteam/`.

## How it is built

SawOne-SI is a profile and a set of analysers on the Sawone engine: `scanner/profile.yml` declares its stages,
their phases, wording (English and Arabic), the AI rule pack, the compliance controls and the AI report chapter;
`scanner/sawone_si.py` adds the stages to Sawone's scan. The image is built `FROM` the Sawone release named in
`ENGINE_VERSION`, whose signature `release.yml` verifies first, so report, phases, threat model, risk policy and
Arabic rendering stay identical across the Sawone family. The red-team runner is a separate image
(`redteam/`) holding garak and promptfoo.

## Limitations

- **Model files are read as data, never loaded.** The model scan flags unsafe formats and dangerous constructs
  (pickle opcodes, Lambda layers, GGUF template escapes); it does not prove a file is safe, so safetensors/ONNX
  from a trusted source is still the right default.
- **Static detection.** Detection and the data/prompt checks are pattern-based: they find what is declared and
  present, and can miss heavily dynamic code. The live red-team stage is what exercises the running model.
- **Red teaming needs an endpoint you own**, and is probabilistic — a clean run is evidence, not a guarantee.
- **PII detection** is tuned for Saudi identifiers (national ID/Iqama, IBAN, local mobiles) plus generic
  email/card/JWT; it reports counts and redacted samples for a human to confirm, not a legal determination.

## What is tested

| | How |
|---|---|
| Detection, model scan, PII, config checks, the AI rule pack | `tests/unit/test_analysers.py` |
| The red-team report parsers and gating policy | `tests/unit/test_redteam.py` |
| The whole scan through the Sawone engine: stages, phases, compliance, both PDFs, the AI chapter | `tests/unit/test_scan.py` |
| The reusable workflow as a consumer (scanner built from source) on the vulnai fixture | `validate.yml` → `consumer` / `assert` |
| The red-team image builds and self-tests (configs generated, tools present; no endpoint attacked) | `validate.yml` → `redteam-selftest` |
| **Not** tested automatically | a live red-team run against a real endpoint (needs one you own) |

`tests/fixtures/vulnai` is a deliberately vulnerable AI app; its model files are generated by
`tests/fixtures/make_models.py` and their payloads only `echo` — SawOne-SI never loads them.

## Releasing

Sawone first: SawOne-SI needs the engine release in `ENGINE_VERSION` (`v1.4.0` or later, with product report
sections). Then tag SawOne-SI: `git tag v1.0.0 && git push origin v1.0.0`; make the `sawone-si-scanner` and
`sawone-si-redteam` packages public. Licensed MIT. garak (Apache-2.0) and promptfoo (MIT) run in the separate
red-team image.
