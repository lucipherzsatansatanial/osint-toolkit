import json
from types import SimpleNamespace

from app import ai, phase3, telemetry
from app.modules import threatintel

NOW = 1_800_000_000.0
DATA = {
    "alerts": [
        {"id": 1, "ts": NOW - 30, "title": "[OAI-002] Server called external AI model API — DeepSeek (CN)", "rule": "OAI-002",
         "severity": "high", "domain": "network", "host": "SRV-FILE-02", "user": "unknown", "provider": "DeepSeek",
         "region": "CN", "simulated": False, "incident_id": 1001, "record": "api.deepseek.com"},
        {"id": 2, "ts": NOW - 7200, "title": "[OAI-001] approvals off", "rule": "OAI-001", "severity": "high",
         "domain": "endpoint", "host": "DEV-9", "user": "somchai.k", "simulated": False, "incident_id": 1002,
         "record": "nmap -sV 10.0.5.0/24"},
        {"id": 3, "ts": NOW - 10, "title": "Phishing email quarantined", "severity": "low", "domain": "email",
         "host": "HR-1", "user": "hr.admin"},
    ],
    "agent_audit": [{"ts": NOW - 5, "agent": "hr-bot", "kind": "tool_call", "tool": "files.read", "decision": "denied",
                     "summary": "files.read /srv/.env", "rules": ["AGT-001", "AGT-004"], "on_behalf_of": "hr.admin"}],
    "incidents": [],
}


def fake(monkeypatch, reply, stop="end_turn"):
    calls = []

    class M:
        async def create(self, **kw):
            calls.append(kw)
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=reply)], stop_reason=stop, model=kw["model"],
                                   usage=SimpleNamespace(input_tokens=10, output_tokens=5))
    monkeypatch.setattr(ai, "client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=M())))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    return calls


def nokey(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)


def test_execute_plan_filters_time_and_severity():
    plan = {"source": "alerts", "filters": [{"field": "region", "op": "equals", "value": "CN"},
                                            {"field": "severity", "op": "gte", "value": "high"},
                                            {"field": "bogus", "op": "contains", "value": "x"}],
            "since_minutes": 60, "sort": "newest"}
    out = phase3.execute(plan, DATA, NOW)
    assert out["total"] == 1 and out["results"][0]["id"] == 1 and out["ignored_fields"] == ["bogus"]
    assert phase3.execute({**plan, "since_minutes": 0, "filters": [{"field": "rule", "op": "in", "value": "OAI-001, OAI-002"}]},
                          DATA, NOW)["total"] == 2
    real = phase3.execute({"source": "alerts", "filters": [{"field": "simulated", "op": "equals", "value": "false"}]}, DATA, NOW)
    assert real["total"] == 2


async def test_keyword_fallback(monkeypatch):
    nokey(monkeypatch)
    out = await phase3.nl_hunt("deepseek severity:high", DATA, NOW)
    assert out["mode"] == "keyword" and out["total"] == 1
    out = await phase3.nl_hunt("tool:files.read decision:denied", DATA, NOW)
    assert out["source"] == "agent_audit" and out["total"] == 1


async def test_ai_hunt_question_is_pseudonymised_and_plan_restored(monkeypatch):
    import re
    calls = []

    class Echo:  # behaves like the model: reuses the pseudonym it was given
        async def create(self, **kw):
            calls.append(kw)
            tok = re.search(r"USER_\d+", kw["messages"][0]["content"]).group(0)
            reply = {"source": "alerts", "filters": [{"field": "user", "op": "equals", "value": tok}], "since_minutes": 0,
                     "sort": "newest", "explanation": f"หา alert ของ {tok}", "kql": f"DeviceProcessEvents | where AccountName == '{tok}'"}
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps(reply, ensure_ascii=False))],
                                   stop_reason="end_turn", model=kw["model"], usage=SimpleNamespace(input_tokens=1, output_tokens=1))
    monkeypatch.setattr(ai, "client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=Echo())))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    out = await phase3.nl_hunt("somchai.k ทำอะไรบ้าง", DATA, NOW)
    sent = json.dumps(calls[0]["messages"], ensure_ascii=False)
    assert "somchai" not in sent and calls[0]["output_config"]["format"]["type"] == "json_schema"
    assert out["mode"] == "ai" and out["total"] == 1 and out["plan"]["filters"][0]["value"] == "somchai.k"
    assert "somchai.k" in out["plan"]["kql"]
    calls = fake(monkeypatch, "", stop="refusal")
    assert (await phase3.nl_hunt("x y z", DATA, NOW))["mode"] == "keyword"


def test_local_enrichment_feeds_and_sightings(monkeypatch):
    monkeypatch.setitem(threatintel._cache, "kev", {"data": {"index": {"CVE-2026-1234": {"cve": "CVE-2026-1234", "name": "x"}}}})
    monkeypatch.setitem(threatintel._cache, "feodo", {"data": {"index": {"198.51.100.7": {"ip": "198.51.100.7", "malware": "QakBot"}}}})
    monkeypatch.setitem(threatintel._cache, "agentic", {"data": {"rows": [
        {"type": "user_agent", "value": "HexStrike-HTTP-Framework/1.0", "confidence": "high", "framework": "hexstrike",
         "source": "Elastic", "source_url": "https://x", "context": "ua"}]}})
    assert phase3.local_enrichment("cve-2026-1234", DATA)["matches"][0]["source"] == "CISA KEV"
    r = phase3.local_enrichment("198.51.100.7", DATA)
    assert r["type"] == "ip" and r["local_verdict"] == "malicious"
    r = phase3.local_enrichment("HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)", DATA)
    assert r["matches"][0]["framework"] == "hexstrike"
    r = phase3.local_enrichment("api.deepseek.com", DATA)
    assert r["local_verdict"] == "known_service" and r["sightings"]["incidents"] == [1001]
    assert phase3.local_enrichment("10.1.2.3", DATA)["local_verdict"] == "internal"
    assert phase3.local_enrichment("nothing-here.example", DATA)["local_verdict"] == "unknown"


async def test_enrich_ai_uses_evidence_only(monkeypatch):
    reply = {"verdict": "suspicious", "confidence": "medium", "explanation": "เห็นใน incident 1001", "related_threats": [],
             "recommended_actions": [{"priority": "today", "action": "ยืนยันการอนุมัติ", "owner": "SOC"}], "hunting_ideas": []}
    calls = fake(monkeypatch, json.dumps(reply, ensure_ascii=False))
    out = await phase3.enrich("api.deepseek.com", DATA)
    assert out["ai"]["verdict"] == "suspicious" and "ONLY the evidence" in calls[0]["messages"][0]["content"]
    nokey(monkeypatch)
    assert (await phase3.enrich("api.deepseek.com", DATA))["ai"] is None


def mk_inc(i, t, hosts, users, tactics, sev="high", real=True, alerts=()):
    return {"id": i, "title": f"inc {i}", "severity": sev, "status": "open", "first_ts": t, "last_ts": t + 60,
            "hosts": hosts, "users": users, "domains": ["endpoint"], "tactics": tactics, "real": real,
            "alerts": list(alerts)}


def test_attack_chains_link_on_shared_entities_only():
    incs = [mk_inc(1, NOW, ["WS-1"], ["somchai.k"], ["Initial Access"]),
            mk_inc(2, NOW + 600, ["SRV-DB"], ["somchai.k"], ["Credential Access", "Lateral Movement"]),
            mk_inc(3, NOW + 1200, ["SRV-DB"], ["unknown"], ["Exfiltration"], sev="critical"),
            mk_inc(4, NOW + 100, ["OTHER"], ["unknown"], ["Discovery"]),                        # placeholder user only
            mk_inc(5, NOW + 200, ["WS-1"], ["x"], ["Execution"], real=False),                    # real/sim never mixed
            mk_inc(6, NOW + 3 * 86400, ["SRV-DB"], ["somchai.k"], ["Impact"])]                   # outside 24h window
    chains = phase3.build_chains(incs)
    assert len(chains) == 1
    c = chains[0]
    assert [i["id"] for i in c["incidents"]] == [1, 2, 3] and c["entry"] == 1 and c["severity"] == "critical"
    assert c["tactics"] == ["Initial Access", "Credential Access", "Lateral Movement", "Exfiltration"]
    assert {tuple(e["shared"]) for e in c["edges"]} == {("account:somchai.k",), ("host:SRV-DB",)}
    merged = phase3.chain_as_incident(c, {i["id"]: i for i in incs})
    assert merged["id"] == "CH-1" and merged["coordinated"]


def test_chains_from_simulator_are_built():
    e = telemetry.Engine(seed=2)
    for i in range(900):
        e.step(NOW + i)
    chains = phase3.build_chains(list(e.incidents.values()))
    assert chains and all(len(c["incidents"]) >= 2 for c in chains)
