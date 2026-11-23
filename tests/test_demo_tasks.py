import importlib
import time

from fastapi.testclient import TestClient

from app import demo_tasks, telemetry


def _engine(steps=200):
    eng = telemetry.Engine(seed=7, simulate=True)
    t0 = time.time() - 3 * 3600
    for i in range(steps):
        eng.step(t0 + i * 20)
    return eng


def test_demo_tasks_follow_incident_plans_and_progress():
    eng = _engine()
    now = time.time()
    tasks = demo_tasks.sync(eng, now)
    severe = {i["id"] for i in eng.incidents.values() if i.get("severity") in ("high", "critical")}
    assert tasks and severe
    assert {t["incident_id"] for t in tasks} <= severe
    assert all(t["id"] < 0 and t["simulated"] and not any(k.startswith("_") for k in t) for t in tasks)
    assert all(t["assignee"] is None or t["assignee"].endswith(".demo") for t in tasks)
    assert max(sum(1 for t in tasks if t["incident_id"] == i) for i in severe) <= demo_tasks.MAX_PER_INCIDENT
    # repeated syncs are stable: same ids, no duplicates
    assert [t["id"] for t in demo_tasks.sync(eng, now)] == [t["id"] for t in tasks]
    later = demo_tasks.sync(eng, now + 6 * 3600)
    statuses = {t["status"] for t in later}
    assert "completed" in statuses and "pending" not in {t["status"] for t in later if t["created_at"] < now - 3 * 3600}
    done = next(t for t in later if t["status"] == "completed")
    assert done["history"][-1]["change"].endswith("completed") and done["completed_at"] >= done["created_at"]


def test_no_demo_tasks_without_simulation():
    eng = telemetry.Engine(seed=1, simulate=False)
    assert demo_tasks.sync(eng, time.time()) == []


def test_api_demo_tasks_read_only_and_plan_tasks(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    H = {"X-API-Key": "secret"}
    with TestClient(app.main.app) as c:
        eng = app.main.hub.engine_for("default")
        t0 = time.time() - 3600
        for i in range(200):
            eng.step(t0 + i * 15)
        r = c.get("/api/soc/tasks", headers=H).json()
        demo = [t for t in r["tasks"] if t.get("simulated")]
        assert demo and sum(r["by_status"].values()) == len(r["tasks"])
        assert c.patch(f"/api/soc/tasks/{demo[0]['id']}", headers=H, json={"status": "completed"}).status_code == 409
        inc = demo[0]["incident_id"]
        made = c.post(f"/api/soc/incidents/{inc}/plan-tasks", headers=H, json={}).json()
        assert made["created"] and all(t["id"] > 0 and t["incident_id"] == inc and t["due"] > time.time() for t in made["created"])
        assert c.post(f"/api/soc/incidents/{inc}/plan-tasks", headers=H, json={}).json()["created"] == []
        tok = c.post("/api/users", headers=H, json={"username": "nok", "role": "analyst"}).json()["token"]
        c.post("/api/users", headers=H, json={"username": "pim", "role": "analyst"})
        assert c.post(f"/api/soc/incidents/{inc}/plan-tasks", headers={"X-API-Key": tok},
                      json={"assignee": "pim"}).status_code == 403  # assigning others needs cases.assign
        assert any(x["module"] == "soc.task" for x in c.get("/api/audit?limit=5", headers=H).json()["rows"])
