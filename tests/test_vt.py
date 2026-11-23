import dataclasses
import importlib

import httpx
import pytest
from fastapi.testclient import TestClient

from app import config, vt

SHA = "a" * 64
REPORT = {"data": {"id": SHA, "type": "file", "attributes": {
    "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 0, "undetected": 60, "timeout": 0},
    "last_analysis_results": {"Zeta": {"category": "malicious", "result": "Trojan.X"},
                              "alpha": {"category": "malicious", "result": "Gen:Variant"},
                              "Clean": {"category": "undetected", "result": None}},
    "reputation": -42, "last_analysis_date": 1_700_000_000, "meaningful_name": "invoice.exe",
    "type_description": "Win32 EXE", "size": 204800, "sha256": SHA, "tags": ["peexe"],
    "popular_threat_classification": {"suggested_threat_label": "trojan.agenttesla"}}}}


@pytest.fixture
def mock_vt(monkeypatch):
    """VirusTotal with a key and a fake HTTP transport; returns the list of requests made."""
    monkeypatch.setattr(config, "settings", dataclasses.replace(config.settings, vt_api_key="k", vt_rate_per_min=4,
                                                                vt_daily_quota=500, vt_block_domains=["corp.example.co.th"]))
    vt.reset()
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        assert req.headers["x-apikey"] == "k"
        if req.url.path.endswith("/files/" + SHA):
            return httpx.Response(200, json=REPORT)
        if req.method == "POST" and req.url.path.endswith("/urls"):
            return httpx.Response(200, json={"data": {"type": "analysis", "id": "u-123"}})
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    monkeypatch.setattr(vt, "http_client", lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                                          headers=kw.get("headers")))
    yield calls
    vt.reset()


@pytest.mark.parametrize("value", ["10.1.2.3", "192.168.0.10", "fileserver.local", "dc01.corp", "intranet",
                                   "https://wiki.internal/page", "https://user:pw@example.com/x", "app.corp.example.co.th"])
def test_internal_indicators_never_leave(mock_vt, value):
    with pytest.raises(vt.VTError):
        vt.target(value)


def test_unsupported_and_supported_targets(mock_vt):
    with pytest.raises(vt.VTError) as e:
        vt.target("CVE-2024-3400")
    assert e.value.code == "unsupported"
    assert vt.target("8.8.8.8") == ("ip", "8.8.8.8")
    assert vt.target("evil[.]com") == ("domain", "evil.com")
    assert vt.target(SHA.upper()) == ("file", SHA)
    assert vt.url_id("http://example.com/") == "aHR0cDovL2V4YW1wbGUuY29tLw"
    assert vt.gui_link("ip", "8.8.8.8") == "https://www.virustotal.com/gui/ip-address/8.8.8.8"


async def test_lookup_summarises_and_caches(mock_vt):
    r = await vt.lookup(SHA)
    assert r["verdict"] == "malicious" and r["malicious"] == 5 and r["engines"] == 66 and r["reputation"] == -42
    assert [f["engine"] for f in r["flagged_by"]] == ["alpha", "Zeta"]
    assert r["threat_label"] == "trojan.agenttesla" and r["name"] == "invoice.exe" and r["cached"] is False
    assert r["last_analysis"] == "2023-11-14 22:13 UTC"
    again = await vt.lookup(SHA.upper())
    assert again["cached"] is True and len(mock_vt) == 1


async def test_not_found_is_cached_and_errors_are_not(mock_vt):
    r = await vt.lookup("example.org")
    assert r["found"] is False and r["verdict"] == "unknown"
    await vt.lookup("example.org")
    assert len(mock_vt) == 1
    bad = await vt.lookup("10.0.0.5")
    assert bad["error"] == "internal" and len(mock_vt) == 1


async def test_rate_limit_stops_before_calling(mock_vt, monkeypatch):
    monkeypatch.setattr(config, "settings", dataclasses.replace(config.settings, vt_rate_per_min=2))
    out = await vt.lookup_many(["a.example.org", "b.example.org", "c.example.org"])
    assert [o.get("error") for o in out] == [None, None, "quota"]
    assert out[2]["retry_after"] > 0 and len(mock_vt) == 2
    assert vt.usage()["used_today"] == 2


async def test_disabled_makes_no_request(monkeypatch):
    monkeypatch.setattr(config, "settings", dataclasses.replace(config.settings, vt_api_key=""))
    r = await vt.lookup("8.8.8.8")
    assert r["error"] == "disabled"
    assert (await vt.osint_check("8.8.8.8"))["skipped"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("OSINT_API_KEY", "secret")
    monkeypatch.setenv("SOC_AUTOSTART", "off")
    import app.audit, app.soc_store, app.rbac, app.main
    for m in (app.config, app.audit, app.soc_store, app.rbac, app.main):
        importlib.reload(m)
    with TestClient(app.main.app) as c:
        yield c


H = {"X-API-Key": "secret"}


def test_api_permissions_confirmation_and_audit(client, mock_vt):
    mk = lambda u, role: client.post("/api/users", headers=H, json={"username": u, "role": role}).json()["token"]
    viewer, analyst, lead = mk("vee", "viewer"), mk("nok", "analyst"), mk("lek", "lead")
    body = {"indicators": [SHA, "10.0.0.9", "example.org"]}
    assert client.post("/api/soc/vt/lookup", headers={"X-API-Key": viewer}, json=body).status_code == 403
    r = client.post("/api/soc/vt/lookup", headers={"X-API-Key": analyst}, json=body).json()
    assert [x.get("verdict") or x.get("error") for x in r["results"]] == ["malicious", "internal", "unknown"]
    assert r["usage"]["used_today"] == 2 and "in_intel" in r["results"][0]
    assert client.get("/api/soc/vt/status", headers={"X-API-Key": viewer}).json()["enabled"] is True
    url = {"url": "https://phish.example.net/login"}
    # analysts have threatintel.curate too; the confirmation is what gates a public submission
    assert client.post("/api/soc/vt/scan-url", headers={"X-API-Key": lead}, json=url).status_code == 422
    ok = client.post("/api/soc/vt/scan-url", headers={"X-API-Key": lead}, json={**url, "confirm_public": True}).json()
    assert ok["analysis_id"] == "u-123"
    assert client.post("/api/soc/vt/scan-url", headers={"X-API-Key": lead},
                       json={"url": "https://intranet.local/x", "confirm_public": True}).status_code == 422
    rows = client.get("/api/audit?limit=20", headers=H).json()["rows"]
    assert {"soc.vt_lookup", "soc.vt_scan_url"} <= {x["module"] for x in rows}
    integ = {i["id"]: i["status"] for i in client.get("/api/soc/integrations", headers=H).json()["integrations"]}
    assert integ["virustotal"] == "configured"
