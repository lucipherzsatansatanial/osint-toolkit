import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.main
    for m in (app.config, app.audit, app.soc_store, app.main):
        importlib.reload(m)

    async def fake_scan(target, *a):
        return {"dns": {"ok": True, "data": {"A": ["1.2.3.4"]}, "ms": 1}}
    for mod in ("domain", "email", "username", "ip", "brand"):
        monkeypatch.setattr(getattr(app.main, mod), "scan", fake_scan)
    with TestClient(app.main.app) as c:
        yield c


BASE = {"analyst": "tester", "purpose": "authorized client assessment"}
H = {"X-API-Key": "secret"}


def test_requires_api_key(client):
    assert client.post("/api/scan", json={**BASE, "module": "domain", "target": "a.com"}).status_code == 401


def test_domain_scan_and_audit(client):
    r = client.post("/api/scan", headers=H, json={**BASE, "module": "domain", "target": "HTTPS://A.com/x", "case_ref": "C1"})
    assert r.status_code == 200 and r.json()["target"] == "a.com"
    hist = client.get("/api/history", headers=H).json()
    assert hist[0]["target"] == "a.com" and hist[0]["case_ref"] == "C1"
    detail = client.get(f"/api/scan/{hist[0]['id']}", headers=H).json()
    assert detail["result"]["dns"]["data"]["A"] == ["1.2.3.4"]


def test_personal_modules_need_legal_basis(client):
    body = {**BASE, "module": "username", "target": "alice"}
    assert client.post("/api/scan", headers=H, json=body).status_code == 422
    assert client.post("/api/scan", headers=H, json={**body, "legal_basis": "consent"}).status_code == 200


def test_invalid_target_and_private_ip(client):
    assert client.post("/api/scan", headers=H, json={**BASE, "module": "domain", "target": "localhost"}).status_code == 422
    assert client.post("/api/scan", headers=H, json={**BASE, "module": "ip", "target": "not-an-ip"}).status_code == 422


def test_meta_and_index(client):
    assert client.get("/api/meta").json()["auth_required"] is True
    assert "OSINT Toolkit" in client.get("/").text


def test_soc_endpoints(client, monkeypatch):
    import app.main
    async def fake_cti(force=False):
        return {"kev": {"ok": True, "data": {"items": []}}}
    monkeypatch.setattr(app.main.threatintel, "get_all", fake_cti)
    assert client.get("/api/soc/snapshot").status_code == 401
    snap = client.get("/api/soc/snapshot", headers=H).json()
    assert snap["simulated"] is True and len(snap["endpoints"]) == 14 and len(snap["agents"]) == 5
    assert client.get("/api/soc/cti", headers=H).json()["kev"]["ok"]
    assert client.get("/soc").status_code == 200


def test_soc_agent_hunt_and_contain(client):
    r = client.get("/api/soc/agents", headers=H).json()
    assert {a["id"] for a in r["agents"]} >= {"support-copilot", "devops-agent"} and len(r["rules"]) == 12
    assert client.get("/api/soc/hunt", headers=H, params={"q": "kind:tool_call"}).json()["results"] == []
    assert client.get("/api/soc/agents/sessions/S-99999", headers=H).status_code == 404
    body = {"contain": True, "analyst": "tester", "reason": "suspected prompt injection"}
    assert client.post("/api/soc/agents/nope/contain", headers=H, json=body).status_code == 404
    assert client.post("/api/soc/agents/support-copilot/contain", headers=H, json=body).json()["status"] == "contained"
    hist = client.get("/api/history", headers=H).json()
    assert hist[0]["module"] == "soc.contain" and hist[0]["target"] == "support-copilot"


def test_soc_offensive_ai_pack(client):
    r = client.get("/api/soc/offensive-ai", headers=H).json()
    assert len(r["rules"]) == 14 and len(r["frameworks"]) == 9
    langs = {q["lang"] for q in r["queries"]}
    assert langs == {"KQL", "SPL", "Sigma"} and all(q["title"] and "comment(" not in q["title"] for q in r["queries"])


def test_soc_ingest_api(client):
    import app.main
    body = [{"kind": "net", "host": "SRV-FILE-02", "dest": "api.moonshot.cn"}, {"kind": "nope"}]
    assert client.post("/api/soc/ingest", json=body).status_code == 401
    r = client.post("/api/soc/ingest", headers=H, json=body).json()
    assert r["accepted"] == 1 and r["rejected"] == 1 and r["alerts_by_rule"].get("OAI-002") == 1
    assert client.post("/api/soc/ingest?format=xml", headers=H, json=body).status_code == 422
    big = b"x" * (app.main.ingest.MAX_BYTES + 1)
    assert client.post("/api/soc/ingest", headers=H, content=big).status_code == 413
    reg = client.post("/api/soc/agents/register", headers=H,
                      json=[{"id": "hr-bot", "scopes": ["hr.read"], "egress": [], "shell": False}]).json()
    assert reg[0]["registered"] is True and reg[0]["account"] == "hr-bot"
    assert client.post("/api/soc/agents/register", headers=H, json=[{"id": "bad id!"}]).status_code == 422


def test_soc_incident_workflow_api(client):
    import app.main
    r = client.post("/api/soc/ingest", headers=H, json=[{"kind": "net", "host": "SRV-FILE-02", "dest": "api.deepseek.com"}]).json()
    assert r["alerts"] == 1
    incs = client.get("/api/soc/incidents", headers=H).json()
    inc_id = incs[0]["id"]
    assert incs[0]["real"] is True
    assert client.patch(f"/api/soc/incidents/{inc_id}", headers=H, json={"analyst": "tester"}).status_code == 422
    assert client.patch(f"/api/soc/incidents/{inc_id}", headers=H, json={"analyst": "tester", "status": "nope"}).status_code == 422
    up = client.patch(f"/api/soc/incidents/{inc_id}", headers=H,
                      json={"analyst": "tester", "status": "investigating", "assignee": "tier2", "note": "checking"}).json()
    assert up["status"] == "investigating" and up["notes"][0]["analyst"] == "tester"
    assert client.patch("/api/soc/incidents/424242", headers=H, json={"analyst": "tester", "note": "x"}).status_code == 404
    rep = client.get(f"/api/soc/incidents/{inc_id}/report", headers=H)
    assert rep.status_code == 200 and "Incident #" in rep.text and "default-src 'none'" in rep.headers["content-security-policy"]
    csv_r = client.get("/api/soc/incidents.csv", headers=H)
    assert csv_r.status_code == 200 and str(inc_id) in csv_r.text
    assert client.get("/api/history", headers=H).json()[0]["module"] == "soc.incident"


def test_soc_notify_api(client):
    st = client.get("/api/soc/notify", headers=H).json()
    assert st["channels"] == [] and st["min_severity"] == "high"
    assert client.post("/api/soc/notify/test", headers=H, json={"analyst": "tester"}).status_code == 409
