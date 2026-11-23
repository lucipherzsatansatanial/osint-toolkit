import importlib
import time

from fastapi.testclient import TestClient


def test_global_search(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    H = {"X-API-Key": "secret"}
    with TestClient(app.main.app) as c:
        eng = app.main.hub.engine_for("default")
        for i in range(150):
            eng.step(time.time() - 2400 + i * 15)
        inc = next(iter(eng.incidents.values()))
        r = c.get(f"/api/soc/search?q=INC-{inc['id']}", headers=H).json()
        case = next(g for g in r["groups"] if g["key"] == "case")
        assert case["items"][0]["href"] == f"#inc-{inc['id']}"
        host = inc["hosts"][0]
        keys = {g["key"] for g in c.get(f"/api/soc/search?q={host}", headers=H).json()["groups"]}
        assert {"case", "alert", "asset"} <= keys
        rule = c.get("/api/soc/search?q=OAI-005", headers=H).json()
        assert any(g["key"] == "rule" for g in rule["groups"])
        cve = c.get("/api/soc/search?q=CVE-2024-3400", headers=H).json()
        assert cve["groups"][0]["key"] == "cve" and cve["groups"][0]["items"][0]["external"]
        assert c.get("/api/soc/search?q=x", headers=H).json()["groups"] == []
        before = len(c.get("/api/audit?limit=200", headers=H).json()["rows"])
        c.get(f"/api/soc/search?q={host}", headers=H)
        c.get(f"/api/soc/search?q={host}&log=1", headers=H)
        rows = c.get("/api/audit?limit=200", headers=H).json()["rows"]
        assert sum(1 for x in rows if x["module"] == "soc.search") == 1 and len(rows) >= before
        # a viewer only searches what a viewer may read (no notebooks.write needed, no tasks hidden), an ingest account nothing
        v = c.post("/api/users", headers=H, json={"username": "vee", "role": "viewer"}).json()["token"]
        assert c.get(f"/api/soc/search?q={host}", headers={"X-API-Key": v}).status_code == 200
        ing = c.post("/api/users", headers=H, json={"username": "ing", "role": "ingest"}).json()["token"]
        assert c.get(f"/api/soc/search?q={host}", headers={"X-API-Key": ing}).status_code == 403
