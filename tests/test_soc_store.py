import importlib
import json

import pytest

from app import ingest, telemetry

NOW = 1_800_000_000.0
BATCH = [
    {"kind": "process", "host": "DEV-9", "pid": 2, "ppid": 1, "image": "nmap",
     "parent_image": "claude", "parent_cmdline": "claude --dangerously-skip-permissions", "ts": NOW},
    {"agent": "hr-bot", "kind": "tool_call", "tool": "files.read", "args": "/srv/.env", "ts": NOW},
]


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "soc.db"))
    import app.config, app.soc_store
    importlib.reload(app.config)
    importlib.reload(app.soc_store)
    app.soc_store.init()
    return app.soc_store


def engine(store):
    e = telemetry.Engine(seed=1, simulate=False)
    e.restore(store.load())
    e.persist = True
    return e


def test_real_state_survives_restart(store):
    e1 = engine(store)
    recs, _ = ingest.parse(json.dumps(BATCH).encode(), "native", now=NOW)
    e1.ingest_external(recs)
    inc_id = next(i for i, inc in e1.incidents.items() if "DEV-9" in inc["hosts"])
    e1.update_incident(inc_id, "analyst.a", status="investigating", assignee="tier2", note="ติดต่อเจ้าของเครื่องแล้ว", now=NOW)

    e2 = engine(store)  # "restart"
    assert {ev["rule"] for ev in e2.events} == {"OAI-001", "AGT-011", "AGT-004"}
    inc = e2.incidents[inc_id]
    assert inc["status"] == "investigating" and inc["assignee"] == "tier2" and inc["notes"][0]["text"].startswith("ติดต่อ")
    assert "DEV-9" in e2.endpoints and e2.agents.agents["hr-bot"]["registered"] is False
    assert len(e2.agents.records) == 1
    assert e2.offai.rule_hits["OAI-001"] == 1 and e2.agents.rule_hits["AGT-011"] == 1
    assert e2.stats(NOW)["mode"]["restored"] == 3
    # new ids continue after persisted ones; new alerts keep correlating into the investigating case
    recs, _ = ingest.parse(json.dumps([{"kind": "process", "host": "DEV-9", "pid": 3, "ppid": 1, "image": "sqlmap",
                                         "ts": NOW + 5}, *[{"kind": "process", "host": "DEV-9", "pid": 10 + i, "ppid": 1,
                                         "image": t, "ts": NOW + 6} for i, t in enumerate(["nuclei", "ffuf", "httpx"])]]).encode(),
                           "native", now=NOW)
    e2.ingest_external(recs)
    new = [ev for ev in e2.events if ev["ts"] >= NOW + 5]
    assert new and min(ev["id"] for ev in new) > max(ev["id"] for ev in e2.events if ev["ts"] == NOW)
    assert any(ev.get("incident_id") == inc_id for ev in new)


def test_simulated_never_persisted_or_mixed(store):
    e = telemetry.Engine(seed=4, simulate=True)
    e.persist = True
    for i in range(300):
        e.step(NOW + i)
    assert store.load()["events"] == [] and store.incidents() == []
    recs, _ = ingest.parse(json.dumps([{"kind": "net", "host": "SRV-FILE-02", "dest": "api.deepseek.com",
                                         "ts": NOW + 299}]).encode(), "native", now=NOW)
    e.ingest_external(recs)
    real = [i for i in e.incidents.values() if i.get("real")]
    assert len(real) == 1 and all(a["simulated"] is False for a in real[0]["alerts"])
    assert [i["id"] for i in store.incidents()] == [real[0]["id"]]


def test_update_validation_and_expire(store):
    e = engine(store)
    recs, _ = ingest.parse(json.dumps([BATCH[0]]).encode(), "native", now=NOW)
    e.ingest_external(recs)
    inc_id = next(iter(e.incidents))
    with pytest.raises(ValueError):
        e.update_incident(inc_id, "a", status="done")
    assert e.update_incident(999999, "a", note="x") is None
    e.expire(NOW + telemetry.CORR_WINDOW + 10)
    assert store.incident(inc_id)["status"] == "closed"
    assert store.incident(inc_id)["history"][-1]["change"].endswith("(idle)")


def test_report_and_csv_escape():
    from app import soc_report
    inc = {"id": 7, "title": "<script>alert(1)</script>", "severity": "high", "status": "investigating", "real": True,
           "first_ts": NOW, "last_ts": NOW, "domains": ["endpoint"], "hosts": ["=HYPERLINK(\"x\")"], "users": ["u"],
           "tactics": ["Execution"], "alerts": [{"ts": NOW, "severity": "high", "domain": "endpoint", "title": "<b>x",
                                                 "technique": "T1059", "rule": "OAI-001"}],
           "notes": [{"ts": NOW, "analyst": "a", "text": "<img src=x onerror=1>"}], "history": []}
    html = soc_report.html_report(inc)
    assert "<script>alert" not in html and "&lt;img src=x" in html and "ข้อมูลจำลอง" not in html
    assert "ข้อมูลจำลอง" in soc_report.html_report({**inc, "real": False})
    csv_text = soc_report.csv_export([inc])
    assert csv_text.startswith("﻿id,") and "'=HYPERLINK" in csv_text
