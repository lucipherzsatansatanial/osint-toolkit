import importlib
import time

from fastapi.testclient import TestClient

from app import nb_gen

NOW = 1_800_000_000.0


def test_case_report_uses_only_case_data():
    inc = {"id": 7, "title": "Mimikatz on FIN-WS-014", "severity": "high", "status": "open", "first_ts": NOW - 600,
           "last_ts": NOW, "hosts": ["FIN-WS-014"], "users": ["somchai.k", "unknown"], "domains": ["endpoint"],
           "alerts": [{"ts": NOW - 600, "severity": "high", "title": "LSASS access", "host": "FIN-WS-014", "technique": "T1003.001",
                       "rule": None, "remote_ip": "198.51.100.7", "cti_match": "abuse.ch Feodo Tracker C2"}]}
    plan = {"progress": 0.5, "steps": [{"phase": "contain", "action": "isolate", "owner": "SOC", "done": True, "done_by": "nok"},
                                       {"phase": "recover", "action": "reimage", "owner": "IT", "done": False}]}
    tasks = [{"incident_id": 7, "status": "in_progress", "name": "collect memory", "assignee": "pim"},
             {"incident_id": 8, "status": "pending", "name": "other case"}]
    title, md = nb_gen.case_report(inc, plan, tasks, NOW)
    assert title.startswith("รายงานการสืบสวน INC-7")
    for s in ("`FIN-WS-014`", "`somchai.k`", "`198.51.100.7`", "abuse.ch Feodo Tracker C2 — 1 alert", "✅ [กักกัน] isolate",
              "⬜ [กู้คืน] reimage", "กำลังทำ · collect memory · pim", "## สิ่งที่พบ"):
        assert s in md, s
    assert "other case" not in md and "`unknown`" not in md


def test_handover_counts():
    ev = [{"ts": NOW - 100, "severity": "critical", "host": "DC-01", "rule": "AGT-006"},
          {"ts": NOW - 200, "severity": "high", "host": "DC-01", "title": "x"},
          {"ts": NOW - 50 * 3600, "severity": "critical", "host": "OLD"}]
    incs = [{"id": 1, "severity": "critical", "status": "open", "first_ts": NOW - 300, "last_ts": NOW, "title": "a"},
            {"id": 2, "severity": "low", "status": "open", "first_ts": NOW - 300}]
    tasks = [{"status": "awaiting_input", "name": "ask owner", "incident_id": 1},
             {"status": "pending", "name": "late", "due": NOW - 10}, {"status": "completed", "name": "done"}]
    _, md = nb_gen.handover(ev, incs, tasks, 3, NOW, 12)
    assert "**Alerts:** 2 (critical 1 · high 1" in md and "ยังไม่มีผู้รับผิดชอบ 1" in md
    assert "เลยกำหนด 1 · รอข้อมูล 1" in md and "**คำขอรออนุมัติ:** 3" in md
    assert "**INC-1** critical" in md and "`DC-01` — 2" in md and "OLD" not in md


def test_api_generate_and_demo(tmp_path, monkeypatch):
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
        lst = c.get("/api/soc/notebooks", headers=H).json()["notebooks"]
        demo = [n for n in lst if n.get("simulated")]
        assert demo and demo[0]["title"].startswith("ส่งเวร") and all(n["id"] < 0 for n in demo)
        assert c.put(f"/api/soc/notebooks/{demo[0]['id']}", headers=H, json={"content": "x"}).status_code == 409
        assert app.soc_store.notebooks("default") == []
        inc = next(n["case_id"] for n in demo if n["case_id"])
        nb = c.post("/api/soc/notebooks/generate", headers=H, json={"kind": "case", "case_id": inc}).json()
        assert nb["id"] > 0 and nb["case_id"] == inc and f"INC-{inc}" in nb["content"]
        hand = c.post("/api/soc/notebooks/generate", headers=H, json={"kind": "handover", "hours": 6}).json()
        assert "6 ชั่วโมง" in hand["content"]
        assert c.post("/api/soc/notebooks/generate", headers=H, json={"kind": "case"}).status_code == 422
        tok = c.post("/api/users", headers=H, json={"username": "vee", "role": "viewer"}).json()["token"]
        assert c.post("/api/soc/notebooks/generate", headers={"X-API-Key": tok}, json={"kind": "handover"}).status_code == 403
