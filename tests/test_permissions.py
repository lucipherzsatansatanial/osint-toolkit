import importlib
import json
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import rbac

PUBLIC = {"/api/meta", "/api/me", "/healthz", "/readyz", "/api/soc/intake", "/feeds/{token}.{ext}", "/", "/soc"}


def test_every_route_is_guarded_by_a_known_permission():
    src = Path("app/main.py").read_text(encoding="utf-8")
    for m in re.finditer(r'@app\.(get|post|put|patch|delete)\("([^"]+)"[^\n]*\n((?:.*\n){1,8})', src):
        path, body = m.group(2), m.group(3)
        if path in PUBLIC:
            continue
        perm = re.search(r'require\("([^"]+)"\)', body)
        assert perm, f"{m.group(1).upper()} {path} has no permission check"
        assert perm.group(1) in rbac.PERMISSIONS, f"{path} uses unknown permission {perm.group(1)}"
    for p in re.findall(r'need\(who, "([^"]+)"', src):
        assert p in rbac.PERMISSIONS


def test_role_matrix_follows_policy():
    R = rbac.ROLES
    assert not {"soc.export", "osint.export"} & R["viewer"]
    assert not {"respond.execute", "rules.publish", "agents.deploy", "cases.assign"} & R["analyst"]
    assert {"cases.assign", "rules.publish", "rules.rollback", "respond.approve", "agents.approve"} <= R["lead"]
    assert {"users.manage", "roles.manage", "tokens.manage", "audit.read", "integrations.manage", "governance.manage"} <= R["admin"]
    assert R["ingest"] == {"ingest.submit"} and "ingest.submit" not in R["admin"]
    assert R["viewer"] < R["analyst"] < R["lead"] < R["admin"]
    assert set().union(*R.values()) == set(rbac.PERMISSIONS)  # every permission is reachable by some role


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


def user(client, name, role):
    return {"X-API-Key": client.post("/api/users", headers=H, json={"username": name, "role": role}).json()["token"]}


def ingest(client, recs):
    body = "\n".join(json.dumps({**r, "ts": time.time()}) for r in recs)
    return client.post("/api/soc/ingest?format=native", headers=H, content=body).json()


def test_custom_roles_cannot_escalate(client):
    A, L = user(client, "ana", "analyst"), user(client, "lea", "lead")
    adm = user(client, "adm", "admin")
    assert client.put("/api/roles/triage", headers=L, json={"permissions": ["soc.read"]}).status_code == 403  # no roles.manage
    assert client.put("/api/roles/triage", headers=adm, json={"permissions": ["soc.read", "nope.x"]}).status_code == 422
    assert client.put("/api/roles/shipper2", headers=adm, json={"permissions": ["ingest.submit", "soc.read"]}).status_code in (403, 422)
    r = client.put("/api/roles/triage", headers=adm, json={"label": "Triage", "permissions": ["soc.read", "alerts.read", "cases.read",
                                                                                             "cases.update", "alerts.acknowledge"]})
    assert r.status_code == 200 and r.json()["perms"] == sorted(["soc.read", "alerts.read", "cases.read", "cases.update", "alerts.acknowledge"])
    T = user(client, "tri", "triage")
    me = client.get("/api/me", headers=T).json()
    assert me["role"] == "triage" and "cases.close" not in me["permissions"]
    roles = {x["name"] for x in client.get("/api/roles", headers=L).json()["roles"]}
    assert {"viewer", "admin", "triage"} <= roles
    # a lead may read users but cannot change roles; an analyst cannot even list them
    assert client.patch("/api/users/ana", headers=L, json={"role": "lead"}).status_code == 403
    assert client.get("/api/users", headers=A).status_code == 403
    assert client.delete("/api/roles/triage", headers=adm).status_code == 409  # still assigned
    assert client.get("/api/audit", headers=A).status_code == 403 and client.get("/api/audit", headers=L).status_code == 200


def test_case_update_assign_close_are_separate(client):
    adm = user(client, "adm", "admin")
    client.put("/api/roles/editor", headers=adm, json={"permissions": ["soc.read", "cases.read", "cases.update"]})
    Ed, A, L = user(client, "ed", "editor"), user(client, "ana", "analyst"), user(client, "lea", "lead")
    c = client.post("/api/soc/cases", headers=A, json={"name": "case 1"}).json()
    url = f"/api/soc/incidents/{c['id']}"
    assert client.patch(url, headers=Ed, json={"note": "looked", "priority": "high"}).status_code == 200
    assert client.patch(url, headers=Ed, json={"status": "investigating"}).status_code == 200
    assert client.patch(url, headers=Ed, json={"status": "resolved"}).status_code == 403      # needs cases.close
    assert client.patch(url, headers=A, json={"assignee": "lea"}).status_code == 403          # assigning others
    assert client.patch(url, headers=A, json={"assignee": "ana"}).status_code == 200          # taking it yourself
    assert client.patch(url, headers=L, json={"assignee": "ed"}).status_code == 200
    assert client.patch(url, headers=A, json={"status": "resolved", "verdict": "true_positive"}).status_code == 200
    assert client.patch(url, headers=Ed, json={"status": "open"}).status_code == 403          # re-opening = cases.close
    V = user(client, "vee", "viewer")
    assert client.get(f"{url}/report", headers=V).status_code == 403                         # no export for viewers
    assert client.get(f"{url}/report", headers=A).status_code == 200


def test_alert_actions(client):
    ingest(client, [{"kind": "net", "host": "SRV-1", "dest": "api.deepseek.com"}])
    A, L = user(client, "ana", "analyst"), user(client, "lea", "lead")
    al = client.get("/api/soc/alerts", headers=A).json()["items"][0]
    base = {"title": al["title"], "host": al["host"]}
    assert client.post("/api/soc/alerts/action", headers=A, json={**base, "action": "acknowledge"}).json()["state"]["status"] == "acknowledged"
    assert client.post("/api/soc/alerts/action", headers=A, json={**base, "action": "assign", "assignee": "lea"}).status_code == 403
    assert client.post("/api/soc/alerts/action", headers=A, json={**base, "action": "assign", "assignee": "ana"}).status_code == 200
    assert client.post("/api/soc/alerts/action", headers=L, json={**base, "action": "assign", "assignee": "ana"}).status_code == 200
    assert client.post("/api/soc/alerts/action", headers=A, json={**base, "action": "close"}).status_code == 422  # reason needed
    esc = client.post("/api/soc/alerts/action", headers=A, json={**base, "action": "escalate", "reason": "data to China"}).json()
    inc = client.get(f"/api/soc/incidents/{esc['incident_id']}", headers=A).json()
    assert esc["state"]["status"] == "escalated" and inc["priority"] in ("high", "critical")
    assert client.post("/api/soc/alerts/action", headers=A, json={**base, "action": "close", "reason": "approved vendor",
                                                                   "verdict": "benign"}).status_code == 200
    row = client.get("/api/soc/alerts", headers=A).json()["items"][0]
    assert row["status"] == "closed" and row["verdict"] == "benign"
    V = user(client, "vee", "viewer")
    assert client.post("/api/soc/alerts/action", headers=V, json={**base, "action": "acknowledge"}).status_code == 403
    assert client.post("/api/soc/alerts/action", headers=A, json={"title": "nope", "host": "x", "action": "acknowledge"}).status_code == 404


RULE = {"kind": "process", "match": "all", "title": "certutil download", "severity": "high", "technique": "T1105",
        "tactic": "Command and Control", "conditions": [{"field": "image", "op": "contains", "value": "certutil"}],
        "threshold": {"count": 0, "window_sec": 0, "group_by": ""}}


def test_rule_draft_publish_rollback_and_four_eyes(client):
    A, L = user(client, "ana", "analyst"), user(client, "lea", "lead")
    r = client.post("/api/soc/rules", headers=A, json={"rule": RULE}).json()
    rid = r["id"]
    assert r["status"] == "disabled" and r["version"] == 1
    assert client.patch(f"/api/soc/rules/{rid}", headers=A, json={"status": "enabled"}).status_code == 403
    assert client.patch(f"/api/soc/rules/{rid}", headers=L, json={"status": "enabled"}).json()["published_by"] == "lea"
    # edit -> draft; live definition unchanged until published
    d = client.post("/api/soc/rules", headers=A, json={"rule": {**RULE, "id": rid, "title": "certutil v2"}}).json()
    assert d["title"] == "certutil download" and d["draft"]["def"]["title"] == "certutil v2" and d["status"] == "enabled"
    p = client.patch(f"/api/soc/rules/{rid}", headers=L, json={"status": "enabled"}).json()
    assert p["title"] == "certutil v2" and p["version"] == 2 and p["draft"] is None
    assert client.post(f"/api/soc/rules/{rid}/rollback", headers=A, json={"version": 1, "reason": "too noisy"}).status_code == 403
    rb = client.post(f"/api/soc/rules/{rid}/rollback", headers=L, json={"version": 1, "reason": "too noisy"}).json()
    assert rb["title"] == "certutil download" and rb["version"] == 3 and rb["versions"][-1]["note"].startswith("rollback to v1")
    # four-eyes on rules: the last editor cannot publish
    adm = user(client, "adm", "admin")
    client.put("/api/soc/policies", headers=adm, json={"four_eyes_rules": True, "four_eyes_response": True, "four_eyes_agents": True})
    client.post("/api/soc/rules", headers=L, json={"rule": {**RULE, "id": rid, "title": "by lead"}})
    assert client.patch(f"/api/soc/rules/{rid}", headers=L, json={"status": "enabled"}).status_code == 403
    assert client.patch(f"/api/soc/rules/{rid}", headers=adm, json={"status": "enabled"}).json()["title"] == "by lead"


def test_agent_change_approval_and_retire(client):
    A, L = user(client, "ana", "analyst"), user(client, "lea", "lead")
    pend = client.post("/api/soc/agents/register", headers=A, json=[{"id": "fin-bot", "scopes": ["erp.read"], "shell": False}])
    assert pend.status_code == 202
    rid = pend.json()["requests"][0]["id"]
    assert client.post(f"/api/soc/agents/requests/{rid}/decision", headers=A, json={"approve": True}).status_code == 403
    ok = client.post(f"/api/soc/agents/requests/{rid}/decision", headers=L, json={"approve": True, "comment": "ok"}).json()
    assert ok["agent"]["registered"] is True and ok["decided_by"] == "lea"
    assert client.post(f"/api/soc/agents/requests/{rid}/decision", headers=L, json={"approve": True}).status_code == 409
    assert client.post("/api/soc/agents/fin-bot/lifecycle", headers=A, json={"state": "retired", "reason": "replaced"}).status_code == 403
    assert client.post("/api/soc/agents/fin-bot/lifecycle", headers=L, json={"state": "retired", "reason": "replaced by v2"}).status_code == 200
    out = ingest(client, [{"kind": "tool_call", "agent": "fin-bot", "host": "SRV-AI", "tool": "erp.read"}])
    assert out["alerts_by_rule"].get("AGT-011") == 1


def test_exports_and_policies_need_their_permissions(client):
    A, L, V = user(client, "ana", "analyst"), user(client, "lea", "lead"), user(client, "vee", "viewer")
    assert client.get("/api/history.csv", headers=A).status_code == 403 and client.get("/api/history.csv", headers=L).status_code == 200
    assert client.get("/api/soc/incidents.csv", headers=V).status_code == 403
    assert client.get("/api/soc/policies", headers=A).status_code == 403 and client.get("/api/soc/policies", headers=L).status_code == 200
    assert client.put("/api/soc/policies", headers=L, json={"four_eyes_response": False}).status_code == 403
    assert client.post("/api/soc/notify-rules", headers=L, json={"name": "x", "channels": ["in_app"]}).status_code == 403  # integrations.manage
    assert client.post("/api/soc/intakes", headers=L, json={"name": "fw"}).status_code == 403                          # ingest.sources.manage
    assert client.get("/api/soc/events", headers=V).status_code == 200 and client.post("/api/soc/query", headers=V,
                                                                                       json={"query": "events"}).status_code == 403
