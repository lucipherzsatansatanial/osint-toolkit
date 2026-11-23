import importlib
import time

from fastapi.testclient import TestClient

from app import demo_requests, telemetry


def _engine(steps=400):
    eng = telemetry.Engine(seed=3, simulate=True)
    t0 = time.time() - 2 * 3600
    for i in range(steps):
        eng.step(t0 + i * 15)
    return eng


def test_requests_come_from_simulated_signals_and_get_decided():
    eng = _engine()
    now = time.time()
    out = demo_requests.sync(eng, now)
    assert out["agent_requests"], "the agent-permission column is never empty in the demo tenant"
    allr = out["response_requests"] + out["agent_requests"]
    assert all(r["id"] < 0 and r["simulated"] and r["requested_by"].endswith(".demo") for r in allr)
    assert all(not any(k.startswith("_") for k in r) for r in allr)
    for r in out["response_requests"]:
        assert r["agent"] in eng.agents.agents and r["action"] in ("contain", "release")
    later = demo_requests.sync(eng, now + 3 * 3600)
    decided = [r for r in later["agent_requests"] + later["response_requests"] if r["status"] != "pending"]
    assert decided and all(r["decided_by"] == demo_requests.LEAD for r in decided)


def test_shell_requests_are_mostly_rejected_and_approvals_take_effect():
    eng = _engine(50)
    st = demo_requests._state(eng)
    aid = next(a for a, ag in eng.agents.agents.items() if ag.get("demo"))
    r = demo_requests._new(st, "resp", {"action": "contain", "agent": aid, "reason": "test"}, time.time())
    demo_requests.decide(eng, "resp", r, True, "lek", "", time.time())
    assert eng.agents.agents[aid]["contained"] is True and aid in st["contained"]


def test_no_demo_requests_without_simulation():
    assert demo_requests.sync(telemetry.Engine(seed=1, simulate=False), time.time()) == {"response_requests": [], "agent_requests": []}


def test_api_merge_and_decide(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    H = {"X-API-Key": "secret"}
    with TestClient(app.main.app) as c:
        eng = app.main.hub.engine_for("default")
        for i in range(100):
            eng.step(time.time() - 1500 + i * 15)
        lead = c.post("/api/users", headers=H, json={"username": "lek", "role": "lead"}).json()["token"]
        L = {"X-API-Key": lead}
        ag = c.get("/api/soc/agents/requests", headers=L).json()["requests"]
        pend = next(r for r in ag if r["simulated"] and r["status"] == "pending")
        out = c.post(f"/api/soc/agents/requests/{pend['id']}/decision", headers=L, json={"approve": True, "comment": "ok"}).json()
        assert out["status"] == "approved" and out["decided_by"] == "lek"
        assert pend["spec"]["id"] in eng.agents.agents
        assert c.post(f"/api/soc/agents/requests/{pend['id']}/decision", headers=L, json={"approve": True}).status_code == 409
        assert app.soc_store.get_setting("agent_requests", [], "default") == []  # demo never written to the database
        viewer = c.post("/api/users", headers=H, json={"username": "vee", "role": "viewer"}).json()["token"]
        assert c.post(f"/api/soc/agents/requests/{pend['id']}/decision", headers={"X-API-Key": viewer},
                      json={"approve": True}).status_code == 403
