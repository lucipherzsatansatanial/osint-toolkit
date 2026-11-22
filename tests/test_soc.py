import httpx
import respx

from app import telemetry
from app.modules import threatintel

KEV = {"catalogVersion": "2026.11.20", "vulnerabilities": [
    {"cveID": "CVE-2024-0001", "vendorProject": "A", "product": "X", "vulnerabilityName": "old",
     "dateAdded": "2024-01-01", "dueDate": "2024-01-22", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-9999", "vendorProject": "B", "product": "Y", "vulnerabilityName": "new",
     "dateAdded": "2026-11-20", "dueDate": "2026-12-11", "knownRansomwareCampaignUse": "Known"}]}
FEODO = [{"ip_address": "198.51.100.7", "port": 443, "status": "online", "malware": "QakBot",
          "country": "NL", "as_name": "AS1", "first_seen": "2026-11-01 00:00:00", "last_online": "2026-11-21"}]
TF = {"1": [{"ioc_value": "evil.example", "ioc_type": "domain", "threat_type": "botnet_cc",
             "malware_printable": "Cobalt Strike", "confidence_level": 75, "first_seen_utc": "2026-11-21 10:00:00"}]}


def test_parsers():
    k = threatintel.parse_kev(KEV)
    assert k["total"] == 2 and k["items"][0]["cve"] == "CVE-2026-9999" and k["ransomware_linked"] == 1
    f = threatintel.parse_feodo(FEODO)
    assert f["online"] == 1 and f["by_malware"] == {"QakBot": 1}
    t = threatintel.parse_threatfox(TF)
    assert t["total"] == 1 and t["items"][0]["malware"] == "Cobalt Strike"


@respx.mock
async def test_get_all_keeps_stale_on_failure(monkeypatch):
    threatintel._cache.clear()
    respx.get(threatintel.FEEDS["kev"]).mock(return_value=httpx.Response(200, json=KEV))
    respx.get(threatintel.FEEDS["feodo"]).mock(return_value=httpx.Response(200, json=FEODO))
    respx.get(threatintel.FEEDS["threatfox"]).mock(return_value=httpx.Response(401))
    r = await threatintel.get_all(force=True)
    assert r["kev"]["ok"] and r["feodo"]["ok"] and not r["threatfox"]["ok"]
    assert threatintel.c2_ips() == ["198.51.100.7"]
    respx.get(threatintel.FEEDS["kev"]).mock(return_value=httpx.Response(500))
    r = await threatintel.get_all(force=True)
    assert not r["kev"]["ok"] and r["kev"]["stale"] and r["kev"]["data"]["total"] == 2
    threatintel._cache.clear()


def test_engine_correlates_cross_domain():
    e = telemetry.Engine(seed=1)
    t = 1_000_000.0
    a = e._event(telemetry.CAMPAIGN[0], "FIN-WS-014", "finance.ops", t)
    b = e._event(telemetry.CAMPAIGN[3], "FIN-WS-014", "finance.ops", t + 10)
    other = e._event(telemetry.CAMPAIGN[1], "HR-LT-007", "hr.admin", t + 20)
    for ev in (a, b, other):
        e._ingest(ev)
    assert a["incident_id"] == b["incident_id"] != other["incident_id"]
    inc = e.incidents[a["incident_id"]]
    assert inc["coordinated"] and set(inc["domains"]) == {"email", "endpoint"}
    assert inc["severity"] == "critical"  # high escalated one level for multi-domain
    e.expire(t + telemetry.CORR_WINDOW + 100)
    assert inc["status"] == "closed"


def test_engine_runs_and_uses_cti(monkeypatch):
    monkeypatch.setattr(threatintel, "c2_ips", lambda: ["198.51.100.7"])
    e = telemetry.Engine(seed=7)
    t = 2_000_000.0
    for i in range(600):
        e.step(t + i)
    s = e.stats(t + 599)
    assert sum(s["totals"].values()) > 300 and s["tactics"]
    c2 = [x for x in e.events if x["technique"] == "T1071.001" and x.get("remote_ip")]
    assert c2 and all(x["cti_match"] for x in c2)
    assert all(x["simulated"] for x in e.events)
    assert e.snapshot()["simulated"] is True
