#!/usr/bin/env python3
"""The SawOne-SI red-team runner (inside the companion image).

Reads the target from the environment (set by the ai-redteam stage), builds a garak REST generator config and a
promptfoo red-team config for that endpoint, runs whichever tools are enabled, and leaves their reports in the
output directory for SawOne-SI to parse. It never embeds its own attack corpus — the probes are the tools' own.

Environment:
  SAWONE_LLM_ENDPOINT     the chat/completions URL to attack (a test endpoint you own) — required
  SAWONE_LLM_MODEL        model name to send in the request body
  SAWONE_LLM_API          openai | rest | anthropic | ollama (shapes the request/response templates)
  SAWONE_LLM_API_KEY      bearer token, used only in the request header (never logged)
  SAWONE_REDTEAM_PROFILE  quick | full
  SAWONE_REDTEAM_GARAK    1 to run garak (default 1)
  SAWONE_REDTEAM_PROMPTFOO 1 to run promptfoo (default 1)
  SAWONE_REDTEAM_DRYRUN   1 to only write the configs and exit 0 (CI self-test; no network)
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# probe/plugin selection per profile. garak probe names and promptfoo plugin names are the tools' own.
GARAK_PROBES = {
    "quick": ["promptinject", "latentinjection", "leakreplay.LiteratureCloze", "dan.DanInTheWild",
              "encoding.InjectBase64", "xss"],
    "full": ["promptinject", "latentinjection", "leakreplay", "dan", "encoding", "xss", "malwaregen",
             "packagehallucination", "divergence", "glitch", "ansiescape"],
}
PROMPTFOO_PLUGINS = {
    "quick": ["prompt-extraction", "pii", "harmful:privacy", "hijacking", "excessive-agency", "indirect-prompt-injection"],
    "full": ["prompt-extraction", "pii", "harmful:privacy", "harmful", "hijacking", "excessive-agency", "rbac",
             "bola", "bfla", "ssrf", "sql-injection", "shell-injection", "indirect-prompt-injection",
             "ascii-smuggling", "debug-access", "hallucination", "overreliance"],
}
PROMPTFOO_STRATEGIES = {"quick": ["jailbreak", "prompt-injection"],
                        "full": ["jailbreak", "jailbreak:composite", "prompt-injection", "base64", "rot13",
                                 "multilingual", "crescendo"]}


def _headers():
    h = {"Content-Type": "application/json"}
    key = os.environ.get("SAWONE_LLM_API_KEY")
    if key:
        api = os.environ.get("SAWONE_LLM_API", "openai")
        h["x-api-key" if api == "anthropic" else "Authorization"] = key if api == "anthropic" else f"Bearer {key}"
    return h


def garak_config(endpoint, model, api):
    """A garak REST generator that speaks the OpenAI chat shape (the common case) or a plain prompt/response."""
    if api == "anthropic":
        req = {"model": model, "max_tokens": 512, "messages": [{"role": "user", "content": "$INPUT"}]}
        field = "$.content[0].text"
    elif api == "ollama":
        req = {"model": model, "prompt": "$INPUT", "stream": False}
        field = "$.response"
    else:  # openai-compatible chat/completions
        req = {"model": model, "messages": [{"role": "user", "content": "$INPUT"}]}
        field = "$.choices[0].message.content"
    return {"rest": {"RestGenerator": {
        "name": "sawone-si-target", "uri": endpoint, "method": "post", "headers": _headers(),
        "req_template_json_object": req, "response_json": True, "response_json_field": field,
        "request_timeout": 60}}}


def promptfoo_config(endpoint, model, api, profile):
    """A promptfoo red-team config pointed at the endpoint through its generic http provider."""
    if api == "anthropic":
        body = {"model": model, "max_tokens": 512, "messages": [{"role": "user", "content": "{{prompt}}"}]}
        transform = "json.content[0].text"
    elif api == "ollama":
        body = {"model": model, "prompt": "{{prompt}}", "stream": False}
        transform = "json.response"
    else:
        body = {"model": model, "messages": [{"role": "user", "content": "{{prompt}}"}]}
        transform = "json.choices[0].message.content"
    proto = "http" if str(endpoint).startswith("http://") else "https"
    provider = {"id": proto, "config": {"url": endpoint, "method": "POST", "headers": _headers(),
                                          "body": body, "transformResponse": transform}}
    return {"description": "SawOne-SI red team", "targets": [provider],
            "redteam": {"purpose": "An application assistant reachable by end users.",
                        "numTests": 5 if profile == "quick" else 10,
                        "plugins": PROMPTFOO_PLUGINS[profile], "strategies": PROMPTFOO_STRATEGIES[profile]}}


def _redact(obj):
    """A copy of a config with header secret values masked, for logging."""
    import copy
    c = copy.deepcopy(obj)

    def walk(d):
        if isinstance(d, dict):
            for k, v in d.items():
                if k in ("Authorization", "x-api-key") and isinstance(v, str):
                    d[k] = "***redacted***"
                else:
                    walk(v)
        elif isinstance(d, list):
            for v in d:
                walk(v)
    walk(c)
    return c


def run(cmd, log):
    print("+ " + " ".join(cmd), flush=True)
    p = subprocess.run(cmd, capture_output=True, text=True)
    log.write_text((p.stdout or "") + "\n" + (p.stderr or "") + f"\n[exit {p.returncode}]\n")
    if p.returncode not in (0, 1):
        print(p.stdout[-2000:], p.stderr[-2000:], flush=True)
    return p.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    ap.add_argument("--profile", default=os.environ.get("SAWONE_REDTEAM_PROFILE", "quick"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    profile = a.profile if a.profile in ("quick", "full") else "quick"
    endpoint = os.environ.get("SAWONE_LLM_ENDPOINT", "")
    model = os.environ.get("SAWONE_LLM_MODEL") or "gpt-4o"
    api = os.environ.get("SAWONE_LLM_API", "openai")
    dry = os.environ.get("SAWONE_REDTEAM_DRYRUN") == "1"
    if not endpoint and not dry:
        print("SAWONE_LLM_ENDPOINT is not set", file=sys.stderr)
        return 2

    gcfg = garak_config(endpoint or "https://example.invalid/v1/chat/completions", model, api)
    pcfg = promptfoo_config(endpoint or "https://example.invalid/v1/chat/completions", model, api, profile)
    (out / "garak-generator.json").write_text(json.dumps(gcfg, indent=1))
    (out / "promptfoo-redteam.yaml").write_text(json.dumps(pcfg, indent=1))   # promptfoo reads JSON as YAML
    (out / "redteam-config.redacted.json").write_text(json.dumps(
        {"garak": _redact(gcfg), "promptfoo": _redact(pcfg), "profile": profile}, indent=1))
    if dry:
        # CI self-test: validate the configs parse and the tools are installed; do not attack anything
        ok = True
        import importlib.util
        if importlib.util.find_spec("garak") is None:
            print("garak not installed", file=sys.stderr); ok = False
        try:
            res = subprocess.run(["promptfoo", "--version"], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"promptfoo exited with code {res.returncode}: {res.stderr or res.stdout}", file=sys.stderr)
                raise FileNotFoundError
        except (FileNotFoundError, OSError) as e:
            print(f"promptfoo not runnable: {e}", file=sys.stderr); ok = False
        json.loads((out / "garak-generator.json").read_text())
        json.loads((out / "promptfoo-redteam.yaml").read_text())
        scrub_secrets(out)   # leave only the redacted config, same as a real run
        print("dry run: configs written and tools present" if ok else "dry run: a tool is missing")
        return 0 if ok else 3

    try:
        if os.environ.get("SAWONE_REDTEAM_GARAK", "1") == "1":
            probes = ",".join(GARAK_PROBES[profile])
            run(["python", "-m", "garak", "--model_type", "rest",
                 "--generator_option_file", str(out / "garak-generator.json"),
                 "--probes", probes, "--report_prefix", str(out / "garak"),
                 "--parallel_attempts", "8"], out / "garak.log")
            # garak writes <prefix>.report.jsonl next to the prefix
        if os.environ.get("SAWONE_REDTEAM_PROMPTFOO", "1") == "1":
            run(["promptfoo", "redteam", "run", "-c", str(out / "promptfoo-redteam.yaml"),
                 "-o", str(out / "promptfoo.json"), "--no-progress-bar", "--force"], out / "promptfoo.log")
    finally:
        # The generator configs and the tools' own reports can echo the Authorization header: scrub the API key
        # (and the generator config entirely) from everything left in /out before SawOne-SI collects it.
        scrub_secrets(out)
    # success of the runner itself: the reports are what matter, parsed by SawOne-SI
    return 0


def scrub_secrets(out):
    key = os.environ.get("SAWONE_LLM_API_KEY")
    # the config files hold the live header; keep only the redacted copy
    for name in ("garak-generator.json", "promptfoo-redteam.yaml"):
        p = out / name
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass
    if not key:
        return
    for p in out.rglob("*"):
        if not p.is_file():
            continue
        try:
            text = p.read_text(errors="replace")
        except (OSError, ValueError):
            continue
        if key in text:
            try:
                p.write_text(text.replace(key, "***redacted***"))
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
