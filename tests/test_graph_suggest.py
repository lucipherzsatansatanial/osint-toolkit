import importlib
import time

from fastapi.testclient import TestClient


def test_suggest_auto_and_demo_graphs(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    H = {"X-API-Key": "secret"}
    with TestClient(app.main.app) as c:
        eng = app.main.hub.engine_for("default")
        for i in range(200):
            eng.step(time.time() - 3000 + i * 15)
        sug = c.get("/api/soc/graph/suggest", headers=H).json()["suggestions"]
        types = {s["type"] for s in sug}
        assert {"incident", "host"} <= types and all(s["count"] >= 1 for s in sug)
        inc = next(s for s in sug if s["type"] == "incident")["value"]
        g = c.get(f"/api/soc/graph/auto?incident={inc}", headers=H).json()
        ids = {n["id"] for n in g["nodes"]}
        assert f"incident:{inc}" in ids and len(g["nodes"]) <= 45
        assert all(e["from"] in ids and e["to"] in ids for e in g["edges"])
        assert len({tuple(sorted((e["from"], e["to"]))) for e in g["edges"]}) == len(g["edges"])
        lst = c.get("/api/soc/graphs", headers=H).json()["graphs"]
        demo = [x for x in lst if x["simulated"]]
        assert demo and all(x["id"] < 0 for x in demo)
        one = c.get(f"/api/soc/graphs/{demo[0]['id']}", headers=H).json()
        assert one["nodes"] and one["simulated"]
        assert app.soc_store.graphs("default") == []  # demo graphs are never stored
        assert c.put(f"/api/soc/graphs/{demo[0]['id']}", headers=H, json={"name": "x", "nodes": [], "edges": []}).status_code == 404
        tok = c.post("/api/users", headers=H, json={"username": "vee", "role": "viewer"}).json()["token"]
        assert c.get("/api/soc/graph/suggest", headers={"X-API-Key": tok}).status_code == 403
