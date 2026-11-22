import importlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from app import intel, telemetry

NOW = 1_800_000_000.0


@pytest.mark.parametrize("raw,typ,val", [
    ("1.2.3.4", "ipv4", "1.2.3.4"), ("1.2.3.4:443", "ipv4", "1.2.3.4"), ("evil[.]example.com", "domain", "evil.example.com"),
    ("hxxp://bad.example/x", "url", "http://bad.example/x"), ("A" * 64, "sha256", "a" * 64), ("cve-2026-1234", "cve", "CVE-2026-1234"),
    ("x@example.com", "email", "x@example.com"), ("not an ioc", None, None)])
def test_classify(raw, typ, val):
    t, v = intel.classify(raw)
    assert t == typ and (val is None or v == val)


FEEDS = dict(threatfox={"203.0.113.7:8080": {"ioc": "203.0.113.7:8080", "malware": "Cobalt Strike", "confidence": 75,
                                             "first_seen": "2026-11-20 10:00:00 UTC", "threat": "botnet_cc", "tags": ["cs"]},
                        "bad.example.org": {"ioc": "bad.example.org", "malware": "Vidar", "confidence": 50, "first_seen": "2026-11-21"}},
             feodo={"198.51.100.9": {"malware": "QakBot", "status": "online", "first_seen": "2026-11-01"}},
             kev={"CVE-2026-0001": {"vendor": "Acme", "product": "VPN", "date_added": "2026-11-18", "name": "RCE", "ransomware": True}},
             agentic=[{"type": "user_agent", "value": "HexStrike-AI/1.0", "confidence": "high", "framework": "hexstrike",
                       "reported": "2026-10-01", "source_url": "https://example.com/r"}])


def rows():
    return intel.from_feeds(**FEEDS) + [intel._ind("10.9.9.9", "ipv4", "tenant", 90, "amber", "insider")]


def test_search_multi_value_and_not_found():
    r = intel.search(rows(), "203.0.113.7\nnothing.example\n198.51.100.9")
    assert [i["value"] for i in r["items"]][:2] == ["203.0.113.7", "198.51.100.9"] and r["not_found"] == ["nothing.example"]
    assert intel.search(rows(), "qakbot")["total"] == 1
    assert intel.search(rows(), "", types=["cve"])["items"][0]["tlp"] == "clear"


def test_match_in_logs_and_engine_alert():
    idx = intel.build_index(rows())
    assert intel.match({"kind": "net", "dest_ip": "203.0.113.7", "port": 8080}, idx)["threat"] == "Cobalt Strike"
    assert intel.match({"kind": "http", "dst_host": "x", "uri": "/", "ua": "HexStrike-AI/1.0"}, idx)["source"] == "agentic"
    assert intel.match({"kind": "net", "dest": "https://bad.example.org/login"}, idx)["threat"] == "Vidar"
    assert intel.match({"kind": "net", "dest_ip": "8.8.8.8"}, idx) is None
    eng = telemetry.Engine(seed=1, simulate=False)
    eng.ioc_lookup = lambda: idx
    recs = [{"kind": "net", "host": "WS-1", "dest_ip": "10.9.9.9", "port": 22, "ts": NOW},
            {"kind": "net", "host": "WS-1", "dest_ip": "10.9.9.9", "port": 22, "ts": NOW + 5}]  # deduplicated
    r = eng.ingest_external(recs)
    assert r["alerts_by_rule"] == {"IOC-001": 1}
    e = next(e for e in eng.events if e.get("rule") == "IOC-001")
    assert e["indicator"] == "10.9.9.9" and e["severity"] == "high" and e["malware"] == "insider"


def test_feed_select_tlp_and_formats():
    feed = {"types": ["ipv4"], "sources": [], "min_confidence": 60, "max_tlp": "green", "max_size": 10, "sort": "newest"}
    sel = intel.select(rows(), feed)
    assert {i["value"] for i in sel} == {"203.0.113.7", "198.51.100.9"}  # amber tenant IOC excluded
    assert intel.to_text(sel).splitlines()[0] in ("203.0.113.7", "198.51.100.9")
    b = intel.to_stix(intel.select(rows(), {**feed, "types": [], "min_confidence": 0}), "t")
    kinds = {o["type"] for o in b["objects"]}
    assert b["type"] == "bundle" and kinds == {"indicator", "vulnerability"}
    pats = [o["pattern"] for o in b["objects"] if o["type"] == "indicator"]
    assert "[ipv4-addr:value = '203.0.113.7']" in pats and any("User-Agent" in p for p in pats)
    assert all(o["object_marking_refs"] == [intel.TLP_MARKING["clear"]] for o in b["objects"])
    assert intel.to_csv([intel._ind("=cmd", "domain", "tenant", 1)]).splitlines()[1].startswith("'=cmd")


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


def test_tenant_iocs_detect_search_and_feed_pull(client):
    r = client.post("/api/soc/iocs", headers=H, json={"values": "45.66.77.88\nphish-login.example.net, nonsense value",
                                                       "tlp": "green", "confidence": 90, "threat": "phishing kit"}).json()
    assert r["added"] == 2 and r["invalid"] == ["nonsense value"]
    body = json.dumps({"kind": "net", "host": "LT-CFO", "dest_ip": "45.66.77.88", "port": 443, "ts": time.time()})
    out = client.post("/api/soc/ingest?format=native", headers=H, content=body).json()
    assert out["alerts_by_rule"].get("IOC-001") == 1
    s = client.get("/api/soc/intel?q=45.66.77.88", headers=H).json()
    it = s["items"][0]
    assert it["source"] == "tenant" and it["sightings"]["logs"] == 1 and it["sightings"]["alerts"] == 1
    assert it["sightings"]["hosts"] == ["LT-CFO"]
    assert client.get("/api/soc/intel?q=45.66.77.88", headers={"X-API-Key": "secret"}).json()["total"] == 0  # other tenant
    f = client.post("/api/soc/feeds", headers=H, json={"name": "FortiGate EBL", "format": "text", "sources": ["tenant"],
                                                        "types": ["ipv4", "domain"], "max_tlp": "green"}).json()
    path = f["url"].split("://", 1)[1].split("/", 1)[1]
    pulled = client.get("/" + path)
    assert pulled.status_code == 200 and set(pulled.text.split()) == {"45.66.77.88", "phish-login.example.net"}
    assert client.get("/feeds/fd_wrong.txt").status_code == 404
    lst = client.get("/api/soc/feeds", headers=H).json()["feeds"][0]
    assert lst["pulls"] == 1 and lst["would_export"] == 2 and "url" not in lst
    client.put(f"/api/soc/feeds/{f['id']}", headers=H, json={**{k: f[k] for k in ("name", "format", "sources", "types", "max_tlp")}, "enabled": False})
    assert client.get("/" + path).status_code == 404
    assert client.post("/api/soc/iocs/delete", headers=H, json={"values": ["45.66.77.88"]}).json()["deleted"] == 1
    integ = {i["id"]: i for i in client.get("/api/soc/integrations", headers=H).json()["integrations"]}
    assert integ["teams"]["status"] == "available" and integ["ebl_out"]["status"] == "available"
