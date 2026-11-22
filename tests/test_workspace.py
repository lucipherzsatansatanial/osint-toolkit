import importlib
import json

import pytest
from fastapi.testclient import TestClient

from app import telemetry, workspace

NOW = 1_800_000_000.0


def ev(i, title="Mimikatz", host="H1", sev="high", ts=NOW, **kw):
    return {"id": i, "ts": ts, "title": title, "host": host, "severity": sev, "technique": "T1003.001",
            "domain": "endpoint", "rule": None, **kw}


def test_alert_summary_groups_occurrences_and_scores_urgency():
    events = [ev(1, ts=NOW - 50, incident_id=1001), ev(2, ts=NOW - 10, cti_match="KEV"), ev(3, ts=NOW),
              ev(4, title="Port scan", sev="medium"), ev(5, title="noise", sev="info")]
    incs = {1001: {"id": 1001, "status": "investigating", "assignee": "nok", "coordinated": True}}
    out = workspace.alert_summary(events, incs)
    assert [a["title"] for a in out] == ["Mimikatz", "Port scan"]  # info without a rule is dropped
    m = out[0]
    assert m["occurrences"] == 3 and m["first_ts"] == NOW - 50 and m["last_ts"] == NOW
    assert m["status"] == "investigating" and m["assignee"] == "nok"
    assert m["urgency"] == 70 + 2 + 5 + 5
    assert out[1]["urgency"] == 45 and out[1]["status"] == "new"
    assert workspace.urgency("critical", 50, True, True) == 100


def test_top_threats_and_data_sources():
    events = [ev(1), ev(2), ev(3, technique="T1110"), ev(4, ts=NOW - 90000, technique="T1110")]
    top = workspace.top_threats(events, NOW - 86400)
    assert top[0] == {"technique": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "alerts": 2}
    assert top[1]["alerts"] == 1  # the 25 h old alert is outside the window
    eng = telemetry.Engine(seed=1, simulate=True)
    for i in range(30):
        eng.step(NOW + i)
    ds = workspace.data_sources(eng.sources)
    assert ds and all(s["source"].endswith("(จำลอง)") for s in ds)
    assert abs(sum(s["share"] for s in ds) - 1) < 0.01


def test_real_ingest_counts_by_source():
    eng = telemetry.Engine(seed=1, simulate=False)
    eng.ingest_external([{"kind": "process", "host": "H", "ts": NOW, "image": "a.exe"},
                         {"kind": "http", "host": "H", "ts": NOW}], source="Elastic ECS")
    assert eng.sources == {"Elastic ECS · EDR process": 1, "Elastic ECS · Web / proxy": 1}


def test_notifications_for_user():
    tasks = [{"id": 1, "name": "Collect memory", "assignee": "nok", "status": "in_progress", "due": NOW - 1,
              "created_at": NOW - 100, "updated_at": NOW - 5},
             {"id": 2, "name": "done", "assignee": "nok", "status": "completed", "created_at": NOW}]
    incs = [{"id": 1001, "status": "open", "assignee": "nok", "severity": "high", "last_ts": NOW, "title": "x"},
            {"id": 1002, "status": "open", "assignee": None, "severity": "critical", "last_ts": NOW, "title": "y"},
            {"id": 1003, "status": "closed", "assignee": "nok", "severity": "critical", "last_ts": NOW, "title": "z"}]
    n = workspace.notifications("nok", tasks, incs, NOW)
    assert [(x["kind"], x["id"]) for x in n] == [("incident", 1002), ("task", 1), ("incident", 1001)]
    assert "เลยกำหนด" in n[1]["detail"]


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


H = {"X-API-Key": "secret"}


def test_task_lifecycle_tenant_scoped_and_audited(client):
    tok = client.post("/api/users", headers={**H, "X-Tenant": "acme"}, json={"username": "nok", "role": "analyst"}).json()["token"]
    view = client.post("/api/users", headers={**H, "X-Tenant": "acme"}, json={"username": "vee", "role": "viewer"}).json()["token"]
    A = {"X-API-Key": tok}
    assert client.get("/api/soc/assignees", headers=A).json()["users"] == ["nok", "vee"]
    assert client.post("/api/soc/tasks", headers=A, json={"name": "x", "assignee": "vee"}).status_code == 403  # analysts cannot assign others
    bad = client.post("/api/soc/tasks", headers={**H, "X-Tenant": "acme"}, json={"name": "x", "assignee": "stranger"})
    assert bad.status_code == 422
    t = client.post("/api/soc/tasks", headers=A, json={"name": "Isolate host SRV-01", "assignee": "nok",
                                                        "due": 1_000_000_000.0, "description": "ติดต่อเจ้าของเครื่อง"}).json()
    assert t["id"] == 1 and t["status"] == "pending" and t["created_by"] == "nok"
    assert client.post("/api/soc/tasks", headers={"X-API-Key": view}, json={"name": "x"}).status_code == 403
    u = client.patch(f"/api/soc/tasks/{t['id']}", headers=A, json={"status": "in_progress", "note": "เริ่มแล้ว"}).json()
    assert u["status"] == "in_progress" and u["history"][-1]["change"].startswith("status pending → in_progress")
    assert client.patch("/api/soc/tasks/1", headers=A, json={}).status_code == 422
    lst = client.get("/api/soc/tasks?status=in_progress&q=isolate", headers=A).json()
    assert [x["id"] for x in lst["tasks"]] == [1] and lst["by_status"] == {"in_progress": 1}
    # other tenants never see it
    assert client.get("/api/soc/tasks", headers=H).json()["tasks"] == []
    assert client.patch("/api/soc/tasks/1", headers=H, json={"status": "cancelled"}).status_code == 404
    rows = client.get("/api/audit?limit=10", headers={**H, "X-Tenant": "acme"}).json()["rows"]
    assert sum(r["module"] == "soc.task" for r in rows) == 2
    notes = client.get("/api/soc/notifications", headers=A).json()
    assert notes["items"][0]["kind"] == "task" and notes["urgent"] == 1  # due date has passed


def test_overview_endpoint(client):
    from app.telemetry import hub
    eng = hub.engine_for("default")
    for i in range(40):
        eng.step(NOW + i)
    o = client.get("/api/soc/overview", headers=H).json()
    assert {"pending_alerts", "opened_cases", "alerts", "data_sources", "top_threats", "tasks"} <= set(o)
    assert o["events_total"] == sum(s["events"] for s in o["data_sources"]) or len(o["data_sources"]) == 12
    assert all(0 <= a["urgency"] <= 100 for a in o["alerts"])
    json.dumps(o)


def test_dashboard_reads_do_not_consume_write_budget(client, monkeypatch):
    import dataclasses
    import app.main
    monkeypatch.setattr(app.main, "settings", dataclasses.replace(app.main.settings, rate_limit_per_min=3,
                                                                  read_rate_limit_per_min=50))
    for _ in range(20):
        assert client.get("/api/soc/tasks", headers=H).status_code == 200
    codes = [client.post("/api/soc/tasks", headers=H, json={"name": f"t{i}"}).status_code for i in range(4)]
    assert codes == [200, 200, 200, 429]
