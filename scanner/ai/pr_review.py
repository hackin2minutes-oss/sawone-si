"""ai/pr_review.py — Post GitHub PR inline review comments from SARIF findings.

When GITHUB_TOKEN + pull-request context are available this module:
  1. Reads every *.sarif file from the reports/sarif/ directory.
  2. Maps each SARIF result to a file + line reachable on the PR diff.
  3. Posts a GitHub Pull Request Review with:
       - An inline comment per finding, with a suggested code fix where possible.
       - A summary comment body with the full gate result table.
  4. Requests CHANGES_REQUESTED if any gate-blocking findings exist, otherwise COMMENT.

Environment variables consumed (all optional — module is a no-op when missing):
  GITHUB_TOKEN            — Personal Access Token or GITHUB_TOKEN from Actions
  GITHUB_REPOSITORY       — owner/repo  (set automatically in Actions)
  GITHUB_SHA              — commit SHA  (set automatically in Actions)
  SAWONE_PR_NUMBER        — PR number override (auto-detected from GITHUB_EVENT_PATH)
  SAWONE_PR_MAX_COMMENTS  — maximum inline comments to post (default 25, max 50)
"""
import json
import os
import re
import urllib.request
import urllib.error
from pathlib import Path

_API = "https://api.github.com"
_MAX_DEFAULT = 25


def _env(key, default=None):
    return os.environ.get(key, default)


def _pr_number():
    n = _env("SAWONE_PR_NUMBER")
    if n:
        return int(n)
    ep = _env("GITHUB_EVENT_PATH")
    if ep:
        try:
            ev = json.loads(Path(ep).read_text())
            return ev.get("pull_request", {}).get("number") or ev.get("number")
        except Exception:
            pass
    return None


def _gh(method, path, body=None, token=None):
    """Minimal GitHub REST call; returns (status_code, parsed_json)."""
    token = token or _env("GITHUB_TOKEN")
    url = f"{_API}{path}" if path.startswith("/") else path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Accept": "application/vnd.github+json",
                                          "Authorization": f"Bearer {token}",
                                          "X-GitHub-Api-Version": "2022-11-28",
                                          "Content-Type": "application/json",
                                          "User-Agent": "SawOne-SI/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return 0, {}


def _get_diff_positions(token, repo, pr_number):
    """Fetch the PR diff and build a map of (filename, absolute_line) -> diff_position."""
    status, _ = _gh("GET", f"/repos/{repo}/pulls/{pr_number}", token=token)
    if status != 200:
        return {}
    _, pr = _gh("GET", f"/repos/{repo}/pulls/{pr_number}/files", token=token)
    if not isinstance(pr, list):
        return {}

    pos_map = {}  # (rel_path, abs_line) -> position_int
    for pf in pr:
        filename = pf.get("filename", "")
        patch = pf.get("patch", "")
        if not patch:
            continue
        position = 0
        current_line = 0
        for raw_line in patch.splitlines():
            if raw_line.startswith("@@"):
                m = re.search(r"\+(\d+)(?:,(\d+))?", raw_line)
                if m:
                    current_line = int(m.group(1)) - 1
                position += 1
                continue
            position += 1
            if raw_line.startswith("-"):
                continue
            current_line += 1
            if not raw_line.startswith("+"):
                pass
            pos_map[(filename, current_line)] = position
    return pos_map


def _sarif_to_comments(sarif_dir, pos_map, max_comments):
    """Convert SARIF files to GitHub review comment dicts; skip findings not on the diff."""
    comments = []
    for sarif_file in sorted(Path(sarif_dir).glob("*.sarif")):
        try:
            doc = json.loads(sarif_file.read_text())
        except Exception:
            continue
        for run in doc.get("runs", []):
            rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in run.get("results", []):
                if len(comments) >= max_comments:
                    break
                rule_id = result.get("ruleId", "")
                msg = result.get("message", {}).get("text", "")
                level = result.get("level", "warning")   # error / warning / note
                for loc in result.get("locations", [])[:1]:
                    phys = loc.get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    line_num = phys.get("region", {}).get("startLine", 1)
                    pos = pos_map.get((uri, line_num)) or pos_map.get((uri.lstrip("./"), line_num))
                    if pos is None:
                        continue   # not in this PR's diff

                    rule = rules.get(rule_id, {})
                    sec_sev = rule.get("properties", {}).get("security-severity", "")
                    tags = rule.get("properties", {}).get("tags", [])

                    severity_label = "🔴 **CRITICAL**" if float(sec_sev or 0) >= 9 \
                        else "🟠 **HIGH**" if float(sec_sev or 0) >= 7 \
                        else "🟡 **MEDIUM**" if float(sec_sev or 0) >= 4 \
                        else "🔵 **LOW**"

                    body = (
                        f"### {severity_label} — `{rule_id}`\n\n"
                        f"{msg}\n\n"
                        + (f"**OWASP/CWE:** {', '.join(tags)}\n\n" if tags else "")
                        + f"<sub>Detected by [SawOne-SI](https://github.com/hackin2minutes-oss/sawone-si) "
                          f"· Rule `{rule_id}`</sub>"
                    )
                    comments.append({
                        "path": uri,
                        "position": pos,
                        "body": body,
                        "_level": level,
                        "_rule": rule_id,
                    })
    return comments


def _build_summary_body(summary_json_path, gate_passed):
    """Build the PR review body text from the gate summary."""
    header = (
        "## 🛡️ SawOne-SI Security Scan Results\n\n"
        + ("✅ **All gates passed.** No blocking findings." if gate_passed
           else "❌ **Security gate failed.** Blocking findings detected — please review the inline comments.")
        + "\n\n"
    )
    try:
        summary = json.loads(Path(summary_json_path).read_text())
        rows = ["| Stage | Status | Details |", "| --- | --- | --- |"]
        for stage, info in summary.get("stages", {}).items():
            icon = "✅" if info.get("passed") else "❌" if info.get("blocking", 0) else "⚠️"
            rows.append(f"| `{stage}` | {icon} {info.get('status', '')} | {info.get('detail', '')} |")
        header += "\n".join(rows) + "\n\n"
    except Exception:
        pass
    header += (
        "_Powered by [SawOne-SI · Sawone Agentic AI Security](https://github.com/marketplace/actions/sawone-agentic-ai-agent-security)_"
    )
    return header


def post_pr_review(reports_dir, log=None):
    """Entry point.  reports_dir is the Path to the scan reports root.

    Returns True if review was posted, False/None if skipped (not a PR context).
    """
    token = _env("GITHUB_TOKEN")
    repo  = _env("GITHUB_REPOSITORY")
    sha   = _env("GITHUB_SHA")
    pr    = _pr_number()
    max_c = int(_env("SAWONE_PR_MAX_COMMENTS") or _MAX_DEFAULT)

    if not (token and repo and pr):
        if log:
            log("pr-review: skipped (not a pull-request context or GITHUB_TOKEN missing)")
        return False

    if log:
        log(f"pr-review: posting review on {repo}#{pr}")

    reports_dir = Path(reports_dir)
    sarif_dir   = reports_dir / "sarif"
    summary_path = reports_dir / "summary.json"

    # Determine if gate passed
    gate_passed = True
    try:
        s = json.loads(summary_path.read_text())
        gate_passed = bool(s.get("passed", True))
    except Exception:
        pass

    # Get diff positions
    pos_map = _get_diff_positions(token, repo, pr)

    # Convert SARIF → comments
    comments = _sarif_to_comments(sarif_dir, pos_map, max_comments=min(max_c, 50))

    event = "COMMENT" if gate_passed else "REQUEST_CHANGES"
    body  = _build_summary_body(summary_path, gate_passed)

    payload = {
        "commit_id": sha or "",
        "body": body,
        "event": event,
        "comments": [{"path": c["path"], "position": c["position"], "body": c["body"]} for c in comments],
    }

    status, resp = _gh("POST", f"/repos/{repo}/pulls/{pr}/reviews", body=payload, token=token)

    if status in (200, 201):
        if log:
            log(f"pr-review: posted review #{resp.get('id')} with {len(comments)} inline comment(s) [{event}]")
        return True
    else:
        if log:
            log(f"pr-review: GitHub API returned {status} — {resp}")
        return False


def annotate_from_sarif(sarif_path, log=None):
    """Emit GitHub Actions annotation lines from a single SARIF file.

    Works in any workflow job (not just PRs) — outputs ::error / ::warning lines.
    """
    try:
        doc = json.loads(Path(sarif_path).read_text())
    except Exception:
        return
    level_map = {"error": "error", "warning": "warning", "note": "notice"}
    for run in doc.get("runs", []):
        for result in run.get("results", []):
            level = level_map.get(result.get("level", "warning"), "warning")
            msg   = result.get("message", {}).get("text", "").replace("\n", " ").replace("%", "%25")
            rule  = result.get("ruleId", "")
            for loc in result.get("locations", [])[:1]:
                phys = loc.get("physicalLocation", {})
                uri  = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 1)
                col  = phys.get("region", {}).get("startColumn", 1)
                print(f"::{level} file={uri},line={line},col={col},title={rule}::{msg}")
