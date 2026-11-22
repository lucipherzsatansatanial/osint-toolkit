import importlib
import sqlite3

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
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
    # four-eyes (default): the request is filed, a second person approves, then it runs
    pend = client.post("/api/soc/agents/support-copilot/contain", headers=H, json=body)
    assert pend.status_code == 202 and pend.json()["status"] == "pending_approval"
    rid = pend.json()["request"]["id"]
    assert client.post(f"/api/soc/response-requests/{rid}/decision", headers=H, json={"approve": True}).status_code == 403
    lead = client.post("/api/users", headers=H, json={"username": "lead.two", "role": "lead"}).json()["token"]
    ok = client.post(f"/api/soc/response-requests/{rid}/decision", headers={"X-API-Key": lead}, json={"approve": True}).json()
    assert ok["status"] == "approved" and ok["result"]["status"] == "contained" and ok["decided_by"] == "lead.two"
    hist = client.get("/api/history", headers=H).json()
    assert hist[0]["module"] == "soc.contain" and hist[0]["target"] == "support-copilot" and hist[0]["analyst"] == "lead.two"


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
    client.put("/api/soc/policies", headers=H, json={"four_eyes_agents": False, "four_eyes_response": True, "four_eyes_rules": False})
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


def test_rbac_roles_and_audit_identity(client):
    mk = lambda u, r: client.post("/api/users", headers=H, json={"username": u, "role": r}).json()["token"]
    tv, ta, tl, ti = mk("view.er", "viewer"), mk("ana.lyst", "analyst"), mk("lead.one", "lead"), mk("shipper", "ingest")
    V, A, L, I = ({"X-API-Key": t} for t in (tv, ta, tl, ti))
    assert client.get("/api/me", headers=A).json()["role"] == "analyst"
    assert client.get("/api/me", headers={"X-API-Key": "soc_wrong"}).status_code == 401
    # viewer: read only
    assert client.get("/api/soc/snapshot", headers=V).status_code == 200
    assert client.get("/api/history", headers=V).status_code == 403            # OSINT history has personal data
    assert client.post("/api/soc/ingest", headers=V, json=[]).status_code == 403
    # ingest account: ingest only
    r = client.post("/api/soc/ingest", headers=I, json=[{"kind": "net", "host": "SRV-Q", "dest": "api.deepseek.com"}])
    assert r.status_code == 200 and client.get("/api/soc/snapshot", headers=I).status_code == 403
    inc_id = client.get("/api/soc/incidents", headers=A).json()[0]["id"]
    # analyst: incident workflow, audit shows the real user even if a different name is typed
    up = client.patch(f"/api/soc/incidents/{inc_id}", headers=A, json={"analyst": "someone.else", "note": "checked"})
    assert up.status_code == 200 and up.json()["notes"][-1]["analyst"] == "ana.lyst"
    assert client.post("/api/soc/agents/support-copilot/contain", headers=A,
                       json={"contain": True, "reason": "test containment"}).status_code == 403
    # lead: requests a response action; it runs only after a different approver (admin) approves
    r = client.post("/api/soc/agents/support-copilot/contain", headers=L, json={"contain": False, "reason": "release after test"})
    assert r.status_code == 202
    assert client.post(f"/api/soc/response-requests/{r.json()['request']['id']}/decision", headers=L, json={"approve": True}).status_code == 403
    assert client.post(f"/api/soc/response-requests/{r.json()['request']['id']}/decision", headers=H,
                       json={"approve": True}).json()["result"]["status"] == "normal"
    # lead can read users but not create them
    assert client.get("/api/users", headers=L).status_code == 200
    assert client.post("/api/users", headers=L, json={"username": "x.y", "role": "viewer"}).status_code == 403
    hist = client.get("/api/history", headers=H).json()
    assert hist[0]["module"] == "soc.release" and "lead.one" in hist[0]["purpose"]
    # admin: rotate + disable; old token stops working
    new = client.post("/api/users/ana.lyst/rotate", headers=H).json()["token"]
    assert client.get("/api/me", headers=A).status_code == 401 and client.get("/api/me", headers={"X-API-Key": new}).status_code == 200
    assert client.patch("/api/users/view.er", headers=H, json={"disabled": True}).status_code == 200
    assert client.get("/api/soc/snapshot", headers=V).status_code == 401
    users = client.get("/api/users", headers=H).json()["users"]
    assert all("token_hash" not in u for u in users) and len(users) == 4
    assert client.post("/api/users", headers=H, json={"username": "Bad Name!", "role": "viewer"}).status_code == 422
    assert client.post("/api/users", headers=H, json={"username": "lead.one", "role": "viewer"}).status_code == 422
    # shared bootstrap key still needs a typed analyst name for audited actions
    assert client.patch(f"/api/soc/incidents/{inc_id}", headers=H, json={"note": "x"}).status_code == 422


def test_ai_endpoints_rbac_and_cache(client, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client.post("/api/soc/ingest", headers=H, json=[{"kind": "net", "host": "SRV-AI-X", "dest": "api.deepseek.com"}])
    inc_id = client.get("/api/soc/incidents", headers=H).json()[0]["id"]
    tv = client.post("/api/users", headers=H, json={"username": "v.only", "role": "viewer"}).json()["token"]
    assert client.post(f"/api/soc/incidents/{inc_id}/ai/summary", headers={"X-API-Key": tv}, json={}).status_code == 403
    assert client.get("/api/soc/ai/status", headers=H).json()["enabled"] is False
    s1 = client.post(f"/api/soc/incidents/{inc_id}/ai/summary", headers=H, json={}).json()
    assert s1["source"] == "rule-based" and s1["recommended_actions"]
    s2 = client.post(f"/api/soc/incidents/{inc_id}/ai/summary", headers=H, json={}).json()
    assert s2["generated_at"] == s1["generated_at"]  # cached on the incident
    assert client.get(f"/api/soc/incidents/{inc_id}", headers=H).json()["ai"]["source"] == "rule-based"
    a = client.post(f"/api/soc/incidents/{inc_id}/ai/ask", headers=H, json={"question": "ทำอะไรต่อ"}).json()
    assert a["source"] == "none"
    assert client.get("/api/history", headers=H).json()[0]["module"] == "soc.ai_ask"


def test_phase3_endpoints(client, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client.post("/api/soc/ingest", headers=H, json=[{"kind": "net", "host": "SRV-P3", "dest": "api.deepseek.com"}])
    r = client.post("/api/soc/hunt/nl", headers=H, json={"question": "deepseek"}).json()
    assert r["mode"] == "keyword" and r["total"] >= 1
    e = client.post("/api/soc/enrich", headers=H, json={"indicator": "api.deepseek.com"}).json()
    assert e["local_verdict"] == "known_service" and e["ai"] is None
    assert "chains" in client.get("/api/soc/chains", headers=H).json()
    assert client.post("/api/soc/chains/CH-999999/ai", headers=H).status_code == 404
    tv = client.post("/api/users", headers=H, json={"username": "v3", "role": "viewer"}).json()["token"]
    assert client.post("/api/soc/enrich", headers={"X-API-Key": tv}, json={"indicator": "x.example"}).status_code == 403
    assert client.get("/api/soc/chains", headers={"X-API-Key": tv}).status_code == 200


def test_phase4_endpoints(client, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rule = {"kind": "net", "match": "all", "title": "moonshot", "severity": "high",
            "conditions": [{"field": "dest", "op": "contains", "value": "moonshot"}]}
    t = client.post("/api/soc/rules/test", headers=H, json={"rule": rule, "test_cases": [
        {"description": "hit", "record_json": '{"kind":"net","host":"S","dest":"api.moonshot.cn"}', "should_match": True}]}).json()
    assert t["errors"] == [] and t["tests"][0]["passed"]
    assert "error" in client.post("/api/soc/rules/draft", headers=H, json={"description": "detect moonshot calls please"}).json()
    ta = client.post("/api/users", headers=H, json={"username": "an.4", "role": "analyst"}).json()["token"]
    saved = client.post("/api/soc/rules", headers={"X-API-Key": ta}, json={"rule": rule}).json()
    assert saved["id"] == "CUS-001" and saved["status"] == "disabled" and saved["created_by"] == "an.4"
    assert client.patch("/api/soc/rules/CUS-001", headers={"X-API-Key": ta}, json={"status": "enabled"}).status_code == 403
    assert client.patch("/api/soc/rules/CUS-001", headers=H, json={"status": "enabled"}).json()["status"] == "enabled"
    r = client.post("/api/soc/ingest", headers=H, json=[{"kind": "net", "host": "SRV-ZZ", "dest": "api.moonshot.cn"}]).json()
    assert r["alerts_by_rule"].get("CUS-001") == 1
    assert client.get("/api/soc/rules", headers=H).json()["rules"][0]["hits"] >= 1
    assert client.post("/api/soc/rules", headers=H, json={"rule": {**rule, "kind": "bad"}}).status_code == 422
    risk = client.get("/api/soc/agents/risk", headers=H).json()["agents"]
    assert risk and {"score", "level", "factors"} <= set(risk[0])
    inc_id = client.get("/api/soc/incidents", headers=H).json()[0]["id"]
    plan = client.get(f"/api/soc/incidents/{inc_id}/response", headers=H).json()
    sid = plan["steps"][0]["id"]
    after = client.post(f"/api/soc/incidents/{inc_id}/response/{sid}", headers={"X-API-Key": ta}, json={"done": True}).json()
    assert after["steps"][0]["done"] and after["steps"][0]["done_by"] == "an.4"
    assert client.get(f"/api/soc/incidents/{inc_id}", headers=H).json()["response"][sid]["done"] is True
    assert client.post(f"/api/soc/incidents/{inc_id}/response/zz-9", headers=H, json={"done": True}).status_code == 404


def test_multi_tenant_isolation(client):
    acme = client.post("/api/users", headers=H, json={"username": "acme.lead", "role": "lead", "tenant": "acme"}).json()["token"]
    ship = client.post("/api/users", headers=H, json={"username": "acme.ship", "role": "ingest", "tenant": "acme"}).json()["token"]
    beta = client.post("/api/users", headers=H, json={"username": "beta.admin", "role": "admin", "tenant": "beta"}).json()["token"]
    A, B = {"X-API-Key": acme}, {"X-API-Key": beta}
    assert client.get("/api/me", headers=A).json()["tenant"] == "acme"
    assert client.post("/api/soc/ingest", headers=A, json=[]).status_code == 403  # people do not ship logs
    client.post("/api/soc/ingest", headers={"X-API-Key": ship}, json=[{"kind": "net", "host": "SRV-ACME", "dest": "api.deepseek.com"}])
    # acme sees its incident, beta and default do not
    assert [i["hosts"] for i in client.get("/api/soc/incidents", headers=A).json()] == [["SRV-ACME"]]
    assert client.get("/api/soc/incidents", headers=B).json() == []
    assert all("SRV-ACME" not in i["hosts"] for i in client.get("/api/soc/incidents", headers=H).json())
    acme_inc = client.get("/api/soc/incidents", headers=A).json()[0]["id"]
    assert client.get(f"/api/soc/incidents/{acme_inc}", headers=B).status_code == 404 or \
        "SRV-ACME" not in client.get(f"/api/soc/incidents/{acme_inc}", headers=B).json().get("hosts", [])
    snap = client.get("/api/soc/snapshot", headers=B).json()
    assert snap["simulated"] is False and snap["endpoints"] == []  # customer tenants never get demo data
    # platform key can switch tenants with X-Tenant
    assert [i["hosts"] for i in client.get("/api/soc/incidents", headers={**H, "X-Tenant": "acme"}).json()] == [["SRV-ACME"]]
    assert "acme" in client.get("/api/tenants", headers=H).json()["tenants"]
    assert client.get("/api/tenants", headers=B).json()["tenants"] == ["beta"]
    # a tenant user cannot pick another tenant, see or manage other tenants' users
    assert client.get("/api/soc/incidents", headers={**B, "X-Tenant": "acme"}).json() == []
    assert {u["username"] for u in client.get("/api/users", headers=B).json()["users"]} == {"beta.admin"}
    assert client.post("/api/users/acme.lead/rotate", headers=B).status_code == 404
    created = client.post("/api/users", headers=B, json={"username": "beta.v", "role": "viewer", "tenant": "acme"}).json()
    assert client.get("/api/me", headers={"X-API-Key": created["token"]}).json()["tenant"] == "beta"
    # audit is tenant-scoped
    assert all(r["tenant"] == "beta" for r in client.get("/api/audit", headers=B).json()["rows"])
    assert client.get("/api/soc/incidents", headers={**H, "X-Tenant": "Bad Tenant!"}).status_code == 422


def test_governance_health_backup_and_audit_chain(client, tmp_path):
    import app.audit
    assert client.get("/healthz").json() == {"ok": True}
    assert client.get("/readyz").json()["database"] is True
    client.post("/api/ai/feedback", headers=H, json={"feature": "summary", "ref": "1001", "rating": "down", "comment": "wrong host"})
    client.post("/api/soc/ingest", headers=H, json=[{"kind": "net", "host": "SRV-G", "dest": "api.deepseek.com"}])
    inc_id = client.get("/api/soc/incidents", headers=H).json()[0]["id"]
    client.post(f"/api/soc/incidents/{inc_id}/ai/summary", headers=H, json={})
    rep = client.get("/api/governance/ai-usage", headers=H).json()
    assert rep["features"]["summary"]["down"] == 1 and rep["features"]["summary"]["calls"] == 1
    assert rep["features"]["summary"]["fallback"] == 1
    v = client.get("/api/audit/verify", headers=H).json()
    assert v["ok"] and v["checked"] >= 2
    # tamper with a row in the middle -> verification fails at that row
    con = sqlite3.connect(app.audit.settings.db_path)
    rid = con.execute("SELECT id FROM scans ORDER BY id LIMIT 1 OFFSET 1").fetchone()[0]
    con.execute("UPDATE scans SET analyst = 'someone-else' WHERE id = ?", (rid,))
    con.commit()
    con.close()
    v = client.get("/api/audit/verify", headers=H).json()
    assert not v["ok"] and v["broken_at"] == rid
    b = client.get("/api/admin/backup", headers=H)
    assert b.status_code == 200 and b.content[:15] == b"SQLite format 3"
    csv_r = client.get("/api/audit.csv", headers=H)
    assert csv_r.status_code == 200 and "module" in csv_r.text.splitlines()[0]
    t = client.post("/api/users", headers=H, json={"username": "ten.admin", "role": "admin", "tenant": "zz"}).json()["token"]
    assert client.get("/api/admin/backup", headers={"X-API-Key": t}).status_code == 403
    assert client.get("/api/audit/verify", headers={"X-API-Key": t}).status_code == 403
