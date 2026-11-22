import importlib
import json
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import ai, assistant


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


def ingest(client, recs):
    body = "\n".join(json.dumps({**r, "ts": time.time()}) for r in recs)
    return client.post("/api/soc/ingest?format=native", headers=H, content=body).json()


def block(**kw):
    return SimpleNamespace(**kw)


def test_assistant_tool_loop_pseudonymises_and_restores(client, monkeypatch):
    ingest(client, [{"kind": "logon", "user": "somchai.k", "dest_host": "DC-01", "src_ip": "10.1.2.3"}])
    seen = {}

    class Msgs:
        calls = 0

        async def create(self, **kw):
            Msgs.calls += 1
            if Msgs.calls == 1:
                assert kw["fallbacks"] == "default" and {t["name"] for t in kw["tools"]} >= {"run_query", "search_intel"}
                return SimpleNamespace(stop_reason="tool_use", model="claude-opus-5-5",
                                       usage=SimpleNamespace(input_tokens=10, output_tokens=5),
                                       content=[block(type="tool_use", id="t1", name="run_query",
                                                      input={"query": 'events | where kind == "logon" | fields user, dest_host, src_ip'})])
            seen["tool_result"] = kw["messages"][-1]["content"][0]["content"]
            pseud = seen["tool_result"]
            user_tok = pseud.split('"user": "')[1].split('"')[0]
            return SimpleNamespace(stop_reason="end_turn", model="claude-opus-5-5",
                                   usage=SimpleNamespace(input_tokens=20, output_tokens=8),
                                   content=[block(type="text", text=f"{user_tok} logon ที่ DC-01")])

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(ai, "client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=Msgs())))
    r = client.post("/api/assistant", headers=H, json={"question": "ใคร logon ที่ DC-01"}).json()
    assert "somchai.k" not in seen["tool_result"] and "10.1.2.3" not in seen["tool_result"]  # pseudonymised for the model
    assert r["answer"] == "somchai.k logon ที่ DC-01" and r["calls"][0]["tool"] == "run_query" and r["calls"][0]["ok"]
    assert r["usage"] == {"input_tokens": 30, "output_tokens": 13}
    rows = client.get("/api/audit?limit=5", headers=H).json()["rows"]
    assert rows[0]["module"] == "ai.assistant"


def test_assistant_tool_errors_and_refusal(client, monkeypatch):
    class Msgs:
        n = 0

        async def create(self, **kw):
            Msgs.n += 1
            if Msgs.n == 1:
                return SimpleNamespace(stop_reason="tool_use", model="m", usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                                       content=[block(type="tool_use", id="a", name="run_query", input={"query": "drop table"}),
                                                block(type="tool_use", id="b", name="nope", input={})])
            res = kw["messages"][-1]["content"]
            assert len(res) == 2 and all(x["is_error"] for x in res)  # both results in ONE user message
            return SimpleNamespace(stop_reason="refusal", model="m", usage=SimpleNamespace(input_tokens=1, output_tokens=0), content=[])

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(ai, "client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=Msgs())))
    r = client.post("/api/assistant", headers=H, json={"question": "x"}).json()
    assert r["source"] == "refusal" and [c["ok"] for c in r["calls"]] == [False, False]


def test_assistant_fallback_without_key(client, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    r = client.post("/api/assistant", headers=H, json={"question": "มี rule ตรวจ mcp ไหม"}).json()
    assert r["source"] == "fallback" and r["calls"][0]["tool"] == "search_rules"
    assert any(x["id"] == "AGT-012" for x in r["data"]["items"])
    r = client.post("/api/assistant", headers=H, json={"question": 'events | where kind == "logon"'}).json()
    assert r["calls"][0]["tool"] == "run_query"


def test_collections_revoke_report_templates_profile_graph(client):
    col = client.post("/api/soc/ioc-collections", headers=H, json={"name": "MAZE RSW", "description": "test"}).json()
    client.post("/api/soc/iocs", headers=H, json={"values": "104.238.158.250\n92.63.194.20", "collection_id": col["id"],
                                                  "kill_chain_phase": "command-and-control", "threat": "Maze", "tlp": "green"})
    assert client.post("/api/soc/iocs", headers=H, json={"values": "1.1.1.1", "collection_id": 99}).status_code == 422
    cols = client.get("/api/soc/ioc-collections", headers=H).json()
    assert cols["collections"][0]["iocs"] == 2
    lst = client.get(f"/api/soc/iocs?collection_id={col['id']}", headers=H).json()
    assert lst["total"] == 2 and lst["iocs"][0]["kill_chain_phase"] == "command-and-control"
    out = ingest(client, [{"kind": "net", "host": "WS-9", "dest_ip": "104.238.158.250", "port": 443}])
    assert out["alerts_by_rule"]["IOC-001"] == 1
    rep = client.get(f"/api/soc/ioc-collections/{col['id']}/report", headers=H).json()
    assert rep["seen"] == 1 and rep["items"][0]["value"] == "104.238.158.250" and rep["hosts"] == ["WS-9"]
    assert client.get(f"/api/soc/ioc-collections/{col['id']}/report?format=csv", headers=H).text.count("\n") == 3
    client.post("/api/soc/iocs/revoke", headers=H, json={"values": ["104.238.158.250"]})
    out = ingest(client, [{"kind": "net", "host": "WS-8", "dest_ip": "104.238.158.250", "port": 443}])
    assert "IOC-001" not in out["alerts_by_rule"]  # revoked IOCs are no longer matched
    # graph expand from real data
    g = client.get("/api/soc/graph/expand?type=host&value=WS-9", headers=H).json()
    assert "indicator:104.238.158.250" in {n["id"] for n in g["nodes"]} and "rule:IOC-001" in {n["id"] for n in g["nodes"]}
    saved = client.post("/api/soc/graphs", headers=H, json={"name": "Maze", "nodes": [g["node"], *g["nodes"]], "edges": g["edges"]}).json()
    assert client.get(f"/api/soc/graphs/{saved['id']}", headers=H).json()["edges"]
    assert client.get("/api/soc/graphs", headers={"X-API-Key": "secret"}).json()["graphs"] == []
    # workspace profile + templates
    w = client.get("/api/soc/workspace", headers=H).json()
    assert "legal_name" in w["missing"]
    w = client.put("/api/soc/workspace", headers=H, json={"display_name": "ACME", "legal_name": "ACME Co., Ltd.", "domain": "ACME.co.th",
                                                         "location": "Thailand", "sector": "Banking / Finance", "size": "201-1000",
                                                         "security_team_size": "1-10"}).json()
    assert w["missing"] == [] and w["profile"]["domain"] == "acme.co.th"
    t = client.put("/api/soc/case-templates", headers=H, json=[{"name": "Phishing", "priority": "high", "tags": ["phishing"],
                                                                "tasks": ["เก็บ header อีเมล", "บล็อกโดเมนผู้ส่ง"]}]).json()["templates"][0]
    c = client.post("/api/soc/cases", headers=H, json={"name": "CFO phishing", "template_id": t["id"], "tags": ["vip"]}).json()
    assert c["tags"] == ["vip", "phishing"] and c["template"] == "Phishing"
    tasks = client.get("/api/soc/tasks", headers=H).json()["tasks"]
    assert {x["name"] for x in tasks if x["incident_id"] == c["id"]} == {"เก็บ header อีเมล", "บล็อกโดเมนผู้ส่ง"}
    ov = client.get("/api/soc/overview", headers=H).json()
    assert ov["recent_cases"][0]["id"] == c["id"] and "alerts_pct" in ov["trend"]
