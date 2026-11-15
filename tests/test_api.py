import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    import app.config, app.audit, app.main
    for m in (app.config, app.audit, app.main):
        importlib.reload(m)

    async def fake_scan(target, *a):
        return {"dns": {"ok": True, "data": {"A": ["1.2.3.4"]}, "ms": 1}}
    for mod in ("domain", "email", "username", "ip", "brand"):
        monkeypatch.setattr(getattr(app.main, mod), "scan", fake_scan)
    with TestClient(app.main.app) as c:
        yield c


BASE = {"analyst": "tester", "purpose": "authorized client assessment"}
H = {"X-API-Key": "secret"}


def test_requires_api_key(client):
    assert client.post("/api/scan", json={**BASE, "module": "domain", "target": "a.com"}).status_code == 401


def test_domain_scan_and_audit(client):
    r = client.post("/api/scan", headers=H, json={**BASE, "module": "domain", "target": "HTTPS://A.com/x", "case_ref": "C1"})
    assert r.status_code == 200 and r.json()["target"] == "a.com"
    hist = client.get("/api/history", headers=H).json()
    assert hist[0]["target"] == "a.com" and hist[0]["case_ref"] == "C1"
    detail = client.get(f"/api/scan/{hist[0]['id']}", headers=H).json()
    assert detail["result"]["dns"]["data"]["A"] == ["1.2.3.4"]


def test_personal_modules_need_legal_basis(client):
    body = {**BASE, "module": "username", "target": "alice"}
    assert client.post("/api/scan", headers=H, json=body).status_code == 422
    assert client.post("/api/scan", headers=H, json={**body, "legal_basis": "consent"}).status_code == 200


def test_invalid_target_and_private_ip(client):
    assert client.post("/api/scan", headers=H, json={**BASE, "module": "domain", "target": "localhost"}).status_code == 422
    assert client.post("/api/scan", headers=H, json={**BASE, "module": "ip", "target": "not-an-ip"}).status_code == 422


def test_meta_and_index(client):
    assert client.get("/api/meta").json()["auth_required"] is True
    assert "OSINT Toolkit" in client.get("/").text
