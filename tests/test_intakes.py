import importlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from app import telemetry

NOW = 1_800_000_000.0


def test_assets_discovered_from_logs_and_alerts():
    from app import ingest
    eng = telemetry.Engine(seed=1, simulate=False)
    raw = "\n".join(json.dumps(r) for r in [
        {"kind": "logon", "user": "somchai.k", "dest_host": "DC-01", "src_host": "LT-07", "ts": NOW},
        {"kind": "logon", "user": "unknown", "dest_host": "DC-01", "ts": NOW + 5},
        {"kind": "tool_call", "agent": "rpa-bot", "host": "SRV-AI", "ts": NOW + 6, "tool": "x"}]).encode()
    eng.ingest_external(ingest.parse(raw, "native")[0], source="Win_DC", entity="ZEN")
    a = eng.assets
    assert a[("host", "DC-01")]["events"] == 2 and a[("host", "DC-01")]["sources"] == ["Win_DC"]
    assert ("account", "unknown") not in a and a[("account", "somchai.k")]["first_seen"] == NOW
    assert a[("ai_agent", "rpa-bot")]["real"] is True
    assert all(r.get("_entity") == "ZEN" for r in eng.raw)


def test_monitor_mode_stores_logs_without_alerts():
    from tests.test_phase4 import RULE, GOOD
    eng = telemetry.Engine(seed=1, simulate=False)
    eng.custom.load([{**RULE, "id": "CUS-001", "status": "enabled"}])
    r = eng.ingest_external([{**GOOD, "ts": NOW}], detect=False)
    assert r["alerts"] == 0 and len(eng.raw) == 1
    r = eng.ingest_external([{**GOOD, "ts": NOW + 1}], entity="BANK")
    assert r["alerts"] >= 1 and all(e["entity"] == "BANK" for e in eng.events)


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


def test_entity_intake_key_flow_counts_and_isolation(client):
    ent = client.post("/api/soc/entities", headers=H, json={"name": "สาขาบางนา", "mode": "automatic"}).json()
    assert client.post("/api/soc/entities", headers=H, json={"name": "สาขาบางนา"}).status_code == 409
    it = client.post("/api/soc/intakes", headers=H, json={"name": "บางนา_Windows", "format": "native", "entity_id": ent["id"]}).json()
    key = it["key"]
    assert key.startswith("ik_") and "key" not in client.get("/api/soc/intakes", headers=H).json()["intakes"][0]
    assert client.post("/api/soc/intake", headers={"X-Intake-Key": "ik_wrong"}, content=b"{}").status_code == 401
    body = "\n".join([json.dumps({"kind": "logon", "user": "u1", "dest_host": "DC-01", "ts": time.time()}),
                      json.dumps({"kind": "net", "host": "FW-01", "dest_ip": "8.8.8.8", "port": 53, "ts": "not-a-date"}),  # unreadable timestamp -> warning
                      json.dumps({"kind": "bogus"})])
    r = client.post("/api/soc/intake", headers={"X-Intake-Key": key}, content=body).json()
    assert r["accepted"] == 2 and r["rejected"] == 1 and r["warnings"] == 1 and r["intake"] == "บางนา_Windows"
    lst = client.get("/api/soc/intakes?days=7", headers=H).json()["intakes"][0]
    assert (lst["valid"], lst["invalid"], lst["warning"], lst["entity"]) == (2, 1, 1, "สาขาบางนา")
    assert client.get("/api/soc/entities", headers=H).json()["entities"][0]["intakes"] == 1
    # logs went to tenant acme only
    ev = client.get("/api/soc/events?minutes=10", headers=H).json()
    assert ev["total"] == 2 and ev["rows"][0]["source"] == "บางนา_Windows"
    assert client.get("/api/soc/events?minutes=10", headers={"X-API-Key": "secret"}).json()["total"] == 0
    # rotate and disable
    new = client.patch(f"/api/soc/intakes/{it['id']}", headers=H, json={"rotate_key": True}).json()["key"]
    assert client.post("/api/soc/intake", headers={"X-Intake-Key": key}, content=b"").status_code == 401
    client.patch(f"/api/soc/intakes/{it['id']}", headers=H, json={"disabled": True})
    assert client.post("/api/soc/intake", headers={"X-Intake-Key": new}, content=b"").status_code == 401


def test_assets_api_list_tag_criticality_revoke(client):
    body = json.dumps({"kind": "logon", "user": "somchai.k", "dest_host": "DC-01"})
    client.post("/api/soc/ingest?format=native", headers=H, content=body)
    r = client.get("/api/soc/assets", headers=H).json()
    assert r["by_type"] == {"host": 1, "account": 1}
    u = client.put("/api/soc/assets", headers=H, json={"type": "host", "name": "DC-01", "tags": ["crown-jewel"], "criticality": 5}).json()
    assert u["tags"] == ["crown-jewel"] and u["criticality"] == 5 and u["events"] == 1
    m = client.put("/api/soc/assets", headers=H, json={"type": "host", "name": "NEW-SRV", "description": "ยังไม่ส่ง log"}).json()
    assert m["manual"] and m["events"] == 0
    assert client.get("/api/soc/assets?sort=criticality", headers=H).json()["items"][0]["name"] == "DC-01"
    client.put("/api/soc/assets", headers=H, json={"type": "account", "name": "somchai.k", "revoked": True})
    assert client.get("/api/soc/assets?type=account", headers=H).json()["total"] == 0
    assert client.get("/api/soc/assets?type=account&revoked=true", headers=H).json()["total"] == 1
    cat = client.get("/api/soc/rules/catalog", headers=H).json()
    assert "Identity logon" in cat["configured_sources"] and "threatfox" in cat["active_iocs"]
    assert next(x for x in cat["rules"] if x["id"] == "OAI-009")["log_sources"] == ["Identity logon", "Network flow"]
