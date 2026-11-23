import importlib
import time

from fastapi.testclient import TestClient

from app import ingest, intel, telemetry, threatmap

NOW = 1_800_000_000.0
DAY = 86400


def ev(i, ts, **kw):
    return {"id": i, "ts": ts, "severity": "high", "tactic": "Execution", "host": "H1", "simulated": False, **kw}


def test_origin_is_never_guessed():
    feodo = {"198.51.100.7": {"country": "NL"}}
    assert threatmap.origin({"src_country": "cn"}, feodo) == "CN"
    assert threatmap.origin({"remote_ip": "198.51.100.7"}, feodo) == "NL"
    assert threatmap.origin({"remote_ip": "203.0.113.9", "src_country": "Thailand"}, feodo) is None


def test_build_counts_windows_and_sources():
    feodo = {"198.51.100.7": {"country": "NL"}, "198.51.100.8": {"country": "NL"}, "192.0.2.1": {"country": "US"}}
    events = [ev(1, NOW - 10, src_country="CN"), ev(2, NOW - 20, src_country="CN", simulated=True),
              ev(3, NOW - 30, remote_ip="198.51.100.7", tactic="Command and Control", host="SRV"),
              ev(4, NOW - 40, src_country="TH"), ev(5, NOW - 50),  # unknown origin
              ev(6, NOW - 9 * DAY, src_country="RU"),  # outside the 7-day window
              ev(7, NOW - 60, src_country="JP", severity="info")]  # info is not an attack
    incs = [{"id": 1, "first_ts": NOW - 100}, {"id": 2, "first_ts": NOW - 2 * DAY}, {"id": 3, "first_ts": NOW - 20 * DAY}]
    inds = [{"value": "1.2.3.4", "type": "ipv4"}, {"value": "1.2.3.4", "type": "ipv4"}, {"value": "x.com", "type": "domain"},
            {"value": "CVE-2024-1", "type": "cve"}]
    out = threatmap.build(events, incs, feodo, inds, "TH", NOW, 7)
    assert out["alerts"] == 5 and out["incidents"] == 2
    assert out["trend"][-1] == 1 and out["trend"][-3] == 1 and out["trend"][9] == 1 and sum(out["trend"]) == 3
    assert out["origins"][0] == {"country": "CN", "count": 2}
    assert out["real_origins"][0] == {"country": "CN", "count": 1}
    assert out["unknown_origin"] == 1 and out["located"] == 4
    assert [a["from"] for a in out["arcs"]] == ["CN", "NL"]  # the home country gets no arc
    assert out["infra"]["top"][0] == {"country": "NL", "count": 2} and out["infra"]["total"] == 3
    assert out["ioc_unique"] == 2 and out["ioc_types"][0] == {"type": "ipv4", "count": 2}
    assert out["categories"][0]["name"] == "Execution" and abs(sum(c["share"] for c in out["categories"]) - 1) < 0.01
    assert out["targets"][0]["host"] == "H1"


def test_shipper_country_reaches_real_alerts():
    rec = ingest.from_ecs({"@timestamp": "2026-11-22T10:00:00Z", "host": {"name": "WEB-01"},
                           "event": {"category": ["web"]}, "http": {"request": {"method": "GET"}},
                           "url": {"path": "/x"}, "source": {"ip": "203.0.113.50", "geo": {"country_iso_code": "VN"}}})
    norm = ingest.clean({**rec, "kind": "http"}, time.time())
    assert norm["src_country"] == "VN"
    assert "src_country" not in ingest.clean({**rec, "kind": "http", "src_country": "Viet Nam"}, time.time())
    eng = telemetry.Engine(seed=1, simulate=False)
    ioc = intel._ind("203.0.113.50", "ipv4", "tenant", 90, threat="test")
    eng.ioc_lookup = lambda: {"203.0.113.50": ioc}
    eng.ingest_external([{**norm, "ts": time.time()}], source="ECS")
    hits = [e for e in eng.step() if e.get("indicator") == "203.0.113.50" or e.get("remote_ip") == "203.0.113.50"]
    assert hits and all(e["src_country"] == "VN" for e in hits)


def test_api(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    monkeypatch.setenv("SOC_HOME_COUNTRY", "sg")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    with TestClient(app.main.app) as c:
        eng = app.main.hub.engine_for("default") if hasattr(app.main, "hub") else None
        if eng:
            for i in range(40):
                eng.step(time.time() + i)
        r = c.get("/api/soc/threatmap?days=99", headers={"X-API-Key": "secret"}).json()
        assert r["days"] == 30 and r["home"] == "SG" and len(r["trend"]) == 30
        assert {"origins", "arcs", "infra", "ioc_types", "categories", "targets"} <= set(r)
        tok = c.post("/api/users", headers={"X-API-Key": "secret"}, json={"username": "ing", "role": "ingest"}).json()["token"]
        assert c.get("/api/soc/threatmap", headers={"X-API-Key": tok}).status_code == 403
