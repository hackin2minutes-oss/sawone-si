"""The red-team adapter: parsing garak and promptfoo reports, and the gating policy.

The live stage needs an endpoint the user owns, so it is not run here; these tests drive the parsers with
synthetic tool output (the shapes garak's report.jsonl and promptfoo's JSON produce)."""
import json

from ai import redteam as RT


def _write(tmp_path, name, obj, lines=False):
    p = tmp_path / name
    if lines:
        p.write_text("\n".join(json.dumps(o) for o in obj))
    else:
        p.write_text(json.dumps(obj))
    return p


def test_configured_requires_an_endpoint():
    assert not RT.configured({})
    assert not RT.configured({"ai": {"redteam": {}}})
    assert RT.configured({"ai": {"redteam": {"endpoint": "https://x/v1/chat/completions"}}})


def test_garak_parser_and_gating(tmp_path):
    rep = _write(tmp_path, "run.report.jsonl", [
        {"entry_type": "eval", "probe": "promptinject.HijackHate", "total": 20, "passed": 8},
        {"entry_type": "eval", "probe": "leakreplay.Literature", "total": 10, "passed": 2},
        {"entry_type": "eval", "probe": "dan.DanInTheWild", "total": 10, "passed": 4},
        {"entry_type": "eval", "probe": "encoding.InjectBase64", "total": 8, "passed": 8},   # all passed
        {"entry_type": "digest", "probe": "ignored"},
    ], lines=True)
    f = {x["id"]: x for x in RT.parse_garak(rep)}
    assert "redteam-garak-promptinject" in f and f["redteam-garak-promptinject"]["gating"]       # LLM01 HIGH blocks
    assert f["redteam-garak-leakreplay"]["gating"] and f["redteam-garak-leakreplay"]["risk"] == "LLM02"
    assert not f["redteam-garak-dan"]["gating"]                       # jailbreak warns, never blocks
    assert "redteam-garak-encoding" not in f                          # fully passed → no finding


def test_promptfoo_parser_and_gating(tmp_path):
    rep = _write(tmp_path, "promptfoo.json", {"results": {"results": [
        {"metadata": {"pluginId": "prompt-extraction"}, "success": False},
        {"metadata": {"pluginId": "pii:direct"}, "success": False},
        {"metadata": {"pluginId": "excessive-agency"}, "success": False},
        {"metadata": {"pluginId": "politics"}, "success": False},
        {"metadata": {"pluginId": "prompt-extraction"}, "success": True},     # defended once
    ]}})
    f = {x["id"]: x for x in RT.parse_promptfoo(rep)}
    assert f["redteam-promptfoo-prompt-extraction"]["gating"] and f["redteam-promptfoo-prompt-extraction"]["risk"] == "LLM07"
    assert f["redteam-promptfoo-pii:direct"]["gating"]
    assert f["redteam-promptfoo-excessive-agency"]["risk"] == "LLM06" and f["redteam-promptfoo-excessive-agency"]["gating"]
    assert not f["redteam-promptfoo-politics"]["gating"]


def test_summary():
    findings = [{"risk": "LLM01", "gating": True}, {"risk": "LLM02", "gating": True}, {"risk": "LLM09", "gating": False}]
    s = RT.summarise(findings)
    assert "3 attack class(es)" in s and "2 blocking" in s
    assert RT.summarise([]) == "no successful attacks"


def test_empty_or_missing_reports_are_safe(tmp_path):
    assert RT.parse_garak(tmp_path / "nope.jsonl") == []
    assert RT.parse_promptfoo(tmp_path / "nope.json") == []
    assert RT.parse_garak(_write(tmp_path, "e.report.jsonl", [], lines=True)) == []
