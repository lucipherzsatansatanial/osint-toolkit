import importlib
import time

from fastapi.testclient import TestClient


def test_collections_from_case_cti_and_demo(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    from app import intel
    H = {"X-API-Key": "secret"}
    with TestClient(app.main.app) as c:
        eng = app.main.hub.engine_for("default")
        for i in range(150):
            eng.step(time.time() - 2400 + i * 15)
        # demo collections are listed, browsable, reportable, never stored
        cols = c.get("/api/soc/ioc-collections", headers=H).json()["collections"]
        demo = [x for x in cols if x.get("simulated")]
        assert demo and all(x["id"] < 0 and x["iocs"] > 0 for x in demo)
        assert c.get(f"/api/soc/iocs?collection_id={demo[0]['id']}", headers=H).json()["total"] == demo[0]["iocs"]
        assert c.get(f"/api/soc/ioc-collections/{demo[0]['id']}/report", headers=H).json()["iocs"] == demo[0]["iocs"]
        assert app.soc_store.iocs("default") == [] and app.soc_store.get_setting("ioc_collections", [], "default") == []
        # a real case with one public and one private IP
        inc_id = eng.create_case("nok", "C2 beacon")["id"]
        eng.incidents[inc_id].setdefault("alerts", []).extend([
            {"ts": time.time(), "title": "beacon", "host": "WS-1", "severity": "high", "remote_ip": "8.8.4.4", "malware": "QakBot"},
            {"ts": time.time(), "title": "lateral", "host": "WS-1", "severity": "high", "remote_ip": "10.0.0.9"}])
        r = c.post("/api/soc/ioc-collections/from-case", headers=H, json={"case_id": inc_id}).json()
        assert r["added"] >= 1 and r["skipped_internal"] >= 1
        stored = {i["value"]: i for i in app.soc_store.iocs("default")}
        assert stored["8.8.4.4"]["tlp"] == "amber" and stored["8.8.4.4"]["collection_id"] == r["collection"]["id"]
        assert "10.0.0.9" not in stored
        again = c.post("/api/soc/ioc-collections/from-case", headers=H, json={"case_id": inc_id}).json()
        assert again["added"] == 0 or again["skipped_existing"] >= 1
        # from CTI: only that threat's feed indicators, as TLP:CLEAR tenant IOCs
        feed = [intel._ind("203.0.113.77", "ipv4", "feodo", 90, threat="Emotet"), intel._ind("evil.example", "domain", "threatfox", 60, threat="Emotet"),
                intel._ind("bad.example", "domain", "threatfox", 60, threat="Other")]
        monkeypatch.setattr(app.main, "_indicators", lambda tenant: feed)
        monkeypatch.setattr(app.main, "_intel_index", lambda tenant: intel.build_index(feed))
        r = c.post("/api/soc/ioc-collections/from-cti", headers=H, json={"threat": "emotet"}).json()
        assert r["added"] == 2 and r["collection"]["name"] == "Emotet (CTI)"
        assert {i["value"] for i in app.soc_store.iocs("default") if i.get("collection_id") == r["collection"]["id"]} == {"203.0.113.77", "evil.example"}
        assert c.post("/api/soc/ioc-collections/from-cti", headers=H, json={"threat": "nope"}).status_code == 422
        sug = c.get("/api/soc/ioc-collections/suggest", headers=H).json()
        assert {"cases", "threats"} <= set(sug) and sug["threats"][0]["threat"] in ("Emotet", "Other")
        tok = c.post("/api/users", headers=H, json={"username": "vee", "role": "viewer"}).json()["token"]
        assert c.post("/api/soc/ioc-collections/from-cti", headers={"X-API-Key": tok}, json={"threat": "Emotet"}).status_code == 403
