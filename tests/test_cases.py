import importlib
import json

import pytest
from fastapi.testclient import TestClient

from app import catalog, query, telemetry

NOW = 1_800_000_000.0
ROWS = [{"kind": "logon", "user": "admin", "host": "DC-01", "port": 3389, "ts": 3},
        {"kind": "net", "user": "svc", "host": "WEB-01", "port": 443, "bytes": 5_000_000, "ts": 2},
        {"kind": "net", "user": "svc", "host": "WEB-02", "port": 22, "bytes": 10, "ts": 1},
        {"kind": "process", "host": "WEB-01", "image": "nmap", "ts": 4}]


def q(text, rows=ROWS):
    return query.run(query.parse(text), rows)


def test_query_language_where_sort_count_fields_limit():
    assert [r["host"] for r in q('events | where kind == "net" and bytes > 1000')["rows"]] == ["WEB-01"]
    assert len(q("events | where port in (22, 3389) or image contains nm")["rows"]) == 3
    assert [r["ts"] for r in q("events | sort by ts desc | limit 2")["rows"]] == [4, 3]
    c = q("events | count by host")
    assert c["aggregated"] and c["rows"][0] == {"host": "WEB-01", "count": 2} and c["columns"] == ["host", "count"]
    f = q("events | where user exists | fields host, user")
    assert f["columns"] == ["host", "user"] and set(f["rows"][0]) == {"host", "user"}
    assert len(q("events | where image !exists")["rows"]) == 3
    assert [r["host"] for r in q('events | where host startswith "web" and kind == net | sort by bytes')["rows"]] == ["WEB-02", "WEB-01"]


@pytest.mark.parametrize("bad", ["select * from x", "events | where", "events | where host", "events | drop x",
                                 "events | limit x", "events | where a in 1", "events |", "events | where a == 1 xor b == 2"])
def test_query_errors_are_explained(bad):
    with pytest.raises(query.QueryError):
        query.parse(bad)


def test_catalog_counts_quality_and_disabled():
    events = [{"rule": "OAI-001", "ts": NOW - 10, "incident_id": 1}, {"rule": "OAI-001", "ts": NOW - 20, "incident_id": 2},
              {"rule": "OAI-001", "ts": NOW - 9 * 86400}, {"rule": "CUS-001", "ts": NOW - 5}]
    incs = {1: {"verdict": "false_positive", "status": "closed"}, 2: {"status": "open"}}
    c = catalog.catalog([{"id": "CUS-001", "title": "x", "severity": "high", "technique": "T1105", "tactic": "Command and Control",
                          "status": "enabled"}], {"AGT-011"}, events, incs, NOW)
    r = {x["id"]: x for x in c["rules"]}
    assert r["OAI-001"]["alerts_7d"] == 2 and r["OAI-001"]["rejected_7d"] == 1 and r["OAI-001"]["quality"] == 50
    assert r["OAI-001"]["exports"] and r["AGT-011"]["enabled"] is False and r["CUS-001"]["alerts_7d"] == 1
    assert r["OAI-003"]["quality"] is None
    assert c["summary"]["total"] == 14 + 12 + 1 and c["summary"]["enabled"] == c["summary"]["total"] - 1
    assert any(t["id"] == "T1059" for m in c["mitre"] for t in m["techniques"])


def test_disabled_rule_suppresses_alerts_and_manual_case_not_glued():
    eng = telemetry.Engine(seed=1, simulate=False)
    case = eng.create_case("nok", "Phishing report from CFO", hosts=["H1"], priority="high", tags=["phishing"])
    from tests.test_phase4 import RULE, GOOD
    eng.custom.load([{**RULE, "id": "CUS-001", "status": "enabled"}])
    eng.ingest_external([{**GOOD, "ts": NOW}])
    assert any(e.get("rule") == "CUS-001" for e in eng.events)
    eng.disabled_rules = {"CUS-001"}
    n = len(eng.events)
    eng.ingest_external([{**GOOD, "ts": NOW + 1}])
    assert eng.suppressed["CUS-001"] == 1 and len(eng.events) == n
    assert case["alerts"] == [] and case["type"] == "manual" and case["severity"] == "high"
    eng.expire(NOW + 10**6)
    assert case["status"] == "open"  # manual cases are never auto-closed
    eng.update_incident(case["id"], "nok", priority="critical", tags=["phishing", "vip"], name="CFO phishing")
    assert case["title"] == "CFO phishing" and case["history"][-1]["change"].startswith("name")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    with TestClient(app.main.app) as c:
        yield c


H = {"X-API-Key": "secret", "X-Tenant": "acme"}


def test_cases_api_fields_and_listing(client):
    assert client.put("/api/soc/case-fields", headers=H, json=[{"key": "bu", "label": "หน่วยธุรกิจ", "type": "select",
                                                                 "options": ["Retail", "Bank"]}]).status_code == 200
    bad = client.post("/api/soc/cases", headers=H, json={"name": "x", "custom_fields": {"bu": "Telco"}})
    assert bad.status_code == 422
    c = client.post("/api/soc/cases", headers=H, json={"name": "CFO phishing", "priority": "high", "tags": ["Phish", "phish", " vip "],
                                                        "hosts": ["LT-CFO"], "custom_fields": {"bu": "Bank"}}).json()
    assert c["tags"] == ["Phish", "vip"] and c["custom_fields"] == {"bu": "Bank"} and c["type"] == "manual"
    u = client.patch(f"/api/soc/incidents/{c['id']}", headers=H, json={"verdict": "true_positive", "priority": "critical", "analyst": "nok"}).json()
    assert u["verdict"] == "true_positive" and u["priority"] == "critical"
    lst = client.get("/api/soc/cases?type=manual&q=cfo", headers=H).json()
    assert lst["total"] == 1 and lst["items"][0]["priority"] == "critical" and lst["tags"] == ["Phish", "vip"]
    assert client.get("/api/soc/cases", headers={"X-API-Key": "secret"}).json()["total"] == 0  # other tenant
    assert client.put("/api/soc/assets/criticality", headers=H, json={"host": "LT-CFO", "level": 5}).status_code == 200
    assert client.get("/api/soc/assets/criticality", headers=H).json()["criticality"] == {"LT-CFO": 5}
    ev = client.get(f"/api/soc/cases/{c['id']}/events", headers=H).json()
    assert ev["hosts"] == ["lt-cfo"]


def test_query_saved_notebooks_and_rule_toggle(client):
    body = "\n".join(json.dumps({"kind": "logon", "user": f"u{i}", "dest_host": "DC-01", "src_ip": "10.1.1.1"}) for i in range(3))
    client.post("/api/soc/ingest?format=native", headers=H, content=body)
    r = client.post("/api/soc/query", headers=H, json={"query": "events | where kind == logon | count by dest_host"}).json()
    assert r["rows"] == [{"dest_host": "DC-01", "count": 3}] and r["scanned"] == 3
    assert client.post("/api/soc/query", headers=H, json={"query": "drop table"}).status_code == 422
    s = client.post("/api/soc/queries", headers=H, json={"name": "logons", "query": "events | where kind == logon"}).json()
    assert client.get("/api/soc/queries", headers=H).json()["queries"][0]["name"] == "logons"
    assert client.delete(f"/api/soc/queries/{s['id']}", headers=H).status_code == 200
    nb = client.post("/api/soc/notebooks", headers=H, json={"title": "Hunt notes", "content": "# test"}).json()
    ok = client.put(f"/api/soc/notebooks/{nb['id']}", headers=H, json={"content": "# v2", "base_updated_at": nb["updated_at"]})
    assert ok.status_code == 200
    stale = client.put(f"/api/soc/notebooks/{nb['id']}", headers=H, json={"content": "# v3", "base_updated_at": nb["updated_at"]})
    assert stale.status_code == 409
    client.put(f"/api/soc/notebooks/{nb['id']}", headers=H, json={"deleted": True})
    assert client.get("/api/soc/notebooks", headers=H).json()["notebooks"] == []
    assert client.get("/api/soc/notebooks?trash=true", headers=H).json()["notebooks"][0]["content"] == "# v2"
    assert client.put("/api/soc/rules/OAI-001/enabled", headers=H, json={"enabled": False}).status_code == 200
    assert client.put("/api/soc/rules/NOPE-1/enabled", headers=H, json={"enabled": False}).status_code == 404
    cat = client.get("/api/soc/rules/catalog", headers=H).json()
    assert next(x for x in cat["rules"] if x["id"] == "OAI-001")["enabled"] is False
