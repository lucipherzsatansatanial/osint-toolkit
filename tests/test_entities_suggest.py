import importlib
import time

from fastapi.testclient import TestClient


def test_entity_suggestions_and_demo_units(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    H = {"X-API-Key": "secret"}
    with TestClient(app.main.app) as c:
        eng = app.main.hub.engine_for("default")
        for i in range(120):
            eng.step(time.time() - 1800 + i * 15)
        ents = c.get("/api/soc/entities", headers=H).json()["entities"]
        demo = [e for e in ents if e.get("simulated")]
        assert any(e["name"] == "ฝ่ายการเงิน (FIN)" for e in demo) and all(e["id"] < 0 for e in demo)
        assert sum(e["alerts_7d"] for e in demo) > 0
        assert app.soc_store.entities("default") == []
        assert c.put(f"/api/soc/entities/{demo[0]['id']}", headers=H, json={"name": "x", "mode": "automatic"}).status_code == 409
        sug = c.get("/api/soc/entities/suggest", headers=H).json()["suggestions"]
        fin = next(g for g in sug if g["prefix"] == "FIN")
        assert fin["hosts"] >= 2 and all(h.startswith("FIN-") for h in fin["examples"])
        made = c.post("/api/soc/entities", headers=H, json={"name": "ฝ่ายการเงิน (FIN)", "description": "d", "mode": "monitor"}).json()
        assert made["id"] > 0
        assert all(g["prefix"] != "FIN" for g in c.get("/api/soc/entities/suggest", headers=H).json()["suggestions"])
        real = next(e for e in c.get("/api/soc/entities", headers=H).json()["entities"] if e["id"] == made["id"])
        assert real["alerts_7d"] == 0 and real["intakes"] == 0
