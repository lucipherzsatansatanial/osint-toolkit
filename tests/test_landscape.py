import importlib
from datetime import date

import pytest
from fastapi.testclient import TestClient

from app import explorer, landscape, notify_rules

NOW = 1_800_000_000.0


def test_malware_and_kev_trends_from_feed_indexes():
    tf = {"a": {"malware": "Cobalt Strike", "first_seen": "2026-11-20 10:00:00 UTC"},
          "b": {"malware": "Cobalt Strike", "first_seen": "2026-11-21 10:00:00 UTC"},
          "c": {"malware": "Vidar", "first_seen": "2026-11-21 11:00:00 UTC"}}
    m = landscape.malware_trend(tf)
    assert m["days"] == ["2026-11-20", "2026-11-21"]
    assert m["series"][0] == {"name": "Cobalt Strike", "points": [1, 1], "total": 2}
    kev = {"CVE-2026-0001": {"cve": "CVE-2026-0001", "vendor": "Acme", "date_added": "2026-11-18", "ransomware": True},
           "CVE-2026-0002": {"cve": "CVE-2026-0002", "vendor": "Acme", "date_added": "2026-11-19", "ransomware": False},
           "CVE-2020-0001": {"cve": "CVE-2020-0001", "vendor": "Old", "date_added": "2020-01-01"}}
    k = landscape.kev_trend(kev, weeks=4, today=date(2026, 11, 22))
    assert k["total"] == 2 and k["ransomware"] == 1 and k["top_vendors"] == [{"vendor": "Acme", "cves": 2}]
    assert sum(k["added"]) == 2 and k["weeks"][-1] == "2026-11-16"
    assert landscape.latest_kev(kev, 1)[0]["cve"] == "CVE-2026-0002"


def test_technique_trend_and_threats_table():
    ev = [{"ts": NOW - 100, "technique": "T1110", "host": "A"}, {"ts": NOW - 4000, "technique": "T1110", "host": "A"},
          {"ts": NOW - 90000, "technique": "T1110", "host": "A"},
          {"ts": NOW - 50, "technique": "T1588.002", "host": "B", "framework": "hexstrike"},
          {"ts": NOW - 60, "technique": "T1071.001", "host": "C", "malware": "QakBot", "cti_match": "Feodo"}]
    t = landscape.technique_trend(ev, NOW, hours=24, buckets=12)
    assert t["series"][0]["technique"] == "T1110" and t["series"][0]["total"] == 2 and sum(t["series"][0]["points"]) == 2
    rows = landscape.threats_table(ev, NOW, {"x": {"malware": "QakBot"}, "y": {"malware": "qakbot"}}, {})
    q = next(r for r in rows if r["threat"] == "QakBot")
    assert q["related_iocs"] == 2 and q["alerts"] == 1 and q["hosts"] == 1
    assert {r["threat"] for r in rows} == {"QakBot", "hexstrike"}


def test_explorer_describe_search_and_histogram():
    recs = [{"kind": "logon", "ts": NOW - 30, "user": "Pornthip", "dest_host": "WH-01", "src_ip": "10.0.0.5",
             "logon_type": 3, "simulated": False},
            {"kind": "http", "ts": NOW - 20, "src_ip": "1.2.3.4", "method": "GET", "dst_host": "web", "uri": "/admin", "status": 403},
            {"kind": "process", "ts": NOW - 10, "host": "SRV", "user": "svc", "image": "nmap", "cmdline": "nmap -sV"},
            {"kind": "process", "ts": NOW - 9999, "host": "OLD", "image": "x"}]
    out = explorer.explore(recs, "", NOW - 300, NOW, buckets=10)
    assert out["total"] == 3 and out["rows"][0]["description"].startswith("SRV · svc ran nmap")
    assert "logged on to WH-01" in out["rows"][2]["description"] and out["rows"][2]["real"]
    assert sum(b["real"] for b in out["histogram"]) == 1 and sum(b["simulated"] for b in out["histogram"]) == 2
    assert explorer.explore(recs, "kind:process -image:x nmap", NOW - 300, NOW)["total"] == 1
    assert explorer.explore(recs, "status:403", NOW - 300, NOW)["total"] == 1


def test_alerts_page_columns_filters_paging():
    events = [{"id": i, "ts": NOW - i, "title": f"A{i % 3}", "host": "H", "severity": "high", "technique": "T1110",
               "tactic": "Credential Access", "rule": "OAI-004" if i % 3 == 0 else None, "domain": "identity",
               "incident_id": 1001 if i % 3 == 1 else None} for i in range(9)]
    incs = {1001: {"id": 1001, "status": "false_positive", "assignee": "nok"}}
    p = explorer.alerts_page(events, incs, size=5, sort="occurrences")
    assert p["total"] == 3 and p["pages"] == 1
    a1 = next(a for a in p["items"] if a["title"] == "A1")
    assert a1["verdict"] == "false_positive" and a1["assignee"] == "nok" and a1["type"] == "Credential Access"
    a0 = next(a for a in p["items"] if a["title"] == "A0")
    assert a0["detection_type"] == "Offensive-AI behaviour" and a0["occurrences"] == 3
    assert explorer.alerts_page(events, incs, status="false_positive")["total"] == 1


INC = {"id": 7, "title": "Coordinated multi-domain attack", "severity": "critical", "real": True, "coordinated": True,
       "domains": ["endpoint", "network"], "alerts": [{"rule": "OAI-001", "title": "AI agent CLI", "cti_match": None}]}


def test_notify_rule_matching():
    base = {"id": 1, "name": "r", "channels": ["in_app"], "min_severity": "high"}
    assert notify_rules.matches(base, INC)
    assert not notify_rules.matches({**base, "domains": ["email"]}, INC)
    assert notify_rules.matches({**base, "rule_prefixes": ["oai-"]}, INC)
    assert not notify_rules.matches({**base, "rule_prefixes": ["AGT-"]}, INC)
    assert not notify_rules.matches({**base, "min_urgency": 99}, INC)
    assert not notify_rules.matches(base, {**INC, "real": False})
    assert notify_rules.matches({**base, "real_only": False, "keyword": "agent cli"}, {**INC, "real": False})
    assert notify_rules.validate({"name": "", "channels": ["fax"]}) == ["ต้องมีชื่อกฎ", "ช่องทางไม่รู้จัก: fax"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.config, app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    importlib.reload(notify_rules)
    import app.main as m2
    m2.notify_rules = notify_rules
    with TestClient(app.main.app) as c:
        yield c


H = {"X-API-Key": "secret"}


def test_rule_fires_in_app_once_and_inbox_read(client):
    from app.telemetry import hub
    r = client.post("/api/soc/notify-rules", headers=H, json={"name": "Critical real", "min_severity": "critical",
                                                              "channels": ["in_app"]})
    assert r.status_code == 200 and r.json()["id"] == 1
    assert client.post("/api/soc/notify-rules", headers=H, json={"name": "x", "channels": []}).status_code == 422
    eng = hub.engine_for("default")
    inc = {**INC, "id": 4242}
    assert eng.on_incident(inc) is True
    assert eng.on_incident(inc) is False  # same severity: no second notification
    n = client.get("/api/soc/notifications", headers=H).json()
    assert n["unread"] == 1 and n["inbox"][0]["ref"] == 4242 and n["inbox"][0]["rule"] == "Critical real"
    assert client.post("/api/soc/notifications/read", headers=H, json={}).json()["marked"] == 1
    assert client.get("/api/soc/notifications", headers=H).json()["unread"] == 0
    assert client.put("/api/soc/notify-rules/1", headers=H, json={"name": "Critical real", "enabled": False,
                                                                  "channels": ["in_app"]}).json()["enabled"] is False
    assert client.delete("/api/soc/notify-rules/1", headers=H).status_code == 200
    rows = client.get("/api/audit?limit=10", headers=H).json()["rows"]
    assert sum(x["module"] == "soc.notify_rule" for x in rows) == 3


def test_events_endpoint_returns_persisted_real_logs(client):
    import json as _j
    body = "\n".join(_j.dumps({"kind": "logon", "user": "u1", "dest_host": "DC-01", "src_ip": "10.1.1.1"}) for _ in range(3))
    assert client.post("/api/soc/ingest?format=native", headers=H, content=body).json()["accepted"] == 3
    out = client.get("/api/soc/events?minutes=60&q=DC-01", headers=H).json()
    assert out["total"] == 3 and all(r["real"] and r["source"] == "API" for r in out["rows"])
    assert client.get("/api/soc/landscape", headers=H).status_code == 200
    assert client.get("/api/soc/alerts?sort=urgency", headers=H).json()["page"] == 1
