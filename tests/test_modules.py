import httpx
import pytest
import respx

from app import validators
from app.modules import brand, common, domain, email, username


def fake_dns(table):
    async def q(name, rtype):
        return table.get((name, rtype), [])
    return q


# ---------- email ----------
def test_spf_assessment():
    assert email.assess_spf([])["risk"] == "high"
    assert email.assess_spf(['"v=spf1 include:_spf.google.com -all"'])["risk"] == "none"
    assert email.assess_spf(['"v=spf1 +all"'])["risk"] == "high"
    assert email.assess_spf(['"v=spf1 a"', '"v=spf1 mx"'])["note"].startswith("Multiple")


def test_dmarc_assessment():
    assert email.assess_dmarc([])["risk"] == "high"
    d = email.assess_dmarc(['"v=DMARC1; p=reject; rua=mailto:d@x.com"'])
    assert d["policy"] == "reject" and d["risk"] == "none" and d["rua"] == "mailto:d@x.com"
    assert email.assess_dmarc(['"v=DMARC1; p=none"'])["risk"] == "medium"


async def test_mail_security(monkeypatch):
    monkeypatch.setattr(email, "dns_query", fake_dns({
        ("x.com", "MX"): ["10 mx.x.com."],
        ("x.com", "TXT"): ['"v=spf1 ~all"'],
        ("_dmarc.x.com", "TXT"): ['"v=DMARC1; p=quarantine"'],
        ("google._domainkey.x.com", "TXT"): ['"v=DKIM1; k=rsa; p=..."'],
    }))
    r = await email.mail_security("x.com")
    assert r["accepts_mail"] and r["spf"]["risk"] == "low"
    assert r["dmarc"]["policy"] == "quarantine" and r["dkim_selectors_found"] == ["google"]


async def test_hibp_skipped_without_key():
    assert "skipped" in await email.hibp_breaches("a@b.com")


# ---------- domain ----------
def test_grade_and_tech():
    g = domain.grade_headers({"strict-transport-security": "max-age=1", "x-frame-options": "DENY"})
    assert g["grade"] == "C" and g["score"] == "2/6"
    tech = domain.detect_tech({"server": "nginx", "cf-ray": "1"}, '<link href="/wp-content/x.css"><script src="jquery.min.js">')
    assert {"Server: nginx", "Cloudflare", "WordPress", "jQuery"} <= set(tech)


@respx.mock
async def test_ct_subdomains_filters_and_dedupes():
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=[
        {"name_value": "*.a.com\nwww.a.com"}, {"name_value": "api.a.com"},
        {"name_value": "evil-a.com"}, {"name_value": "www.a.com"}]))
    r = await domain.ct_subdomains("a.com")
    assert r["subdomains"] == ["a.com", "api.a.com", "www.a.com"]


@respx.mock
async def test_rdap_domain_parses_and_handles_missing_tld():
    respx.get("https://rdap.org/domain/a.com").mock(return_value=httpx.Response(200, json={
        "handle": "H1", "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
        "nameservers": [{"ldhName": "NS1.A.COM"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Registrar Inc"]]]}],
    }))
    respx.get("https://rdap.org/domain/a.co.th").mock(return_value=httpx.Response(404))
    r = await domain.rdap_domain("a.com")
    assert r["age_days"] > 365 and r["entities"][0]["name"] == "Registrar Inc"
    assert (await domain.rdap_domain("a.co.th"))["available"] is False


@respx.mock
async def test_safe_get_blocks_redirect_to_internal(monkeypatch):
    ips = {"good.com": "93.184.216.34", "internal.evil": "10.0.0.5"}
    monkeypatch.setattr(validators.socket, "getaddrinfo", lambda h, p: [(2, 1, 6, "", (ips[h], 0))])
    respx.get("https://good.com/").mock(return_value=httpx.Response(302, headers={"location": "http://internal.evil/admin"}))
    with pytest.raises(validators.ValidationError, match="non-public"):
        await common.safe_get("https://good.com/")


async def test_run_checks_isolates_failures():
    async def ok():
        return 1

    async def boom():
        raise RuntimeError("x")
    r = await common.run_checks({"a": ok, "b": boom})
    assert r["a"]["ok"] and r["a"]["data"] == 1
    assert not r["b"]["ok"] and "RuntimeError" in r["b"]["error"]


# ---------- brand ----------
def test_split_and_permutations():
    assert brand.split_domain("ida.co.th") == ("ida", "co.th")
    assert brand.split_domain("www.google.com") == ("google", "com")
    p = brand.permutations("google.com")
    assert "google.com" not in p
    assert p["gogle.com"] == "omission" and p["g0ogle.com"] == "homoglyph"
    assert p["google.co.th"] == "tld-swap" and len(p) <= brand.MAX_CANDIDATES


async def test_lookalikes_reports_registered(monkeypatch):
    monkeypatch.setattr(brand, "dns_query", fake_dns({
        ("gogle.com", "A"): ["1.2.3.4"], ("gogle.com", "MX"): ["10 mx."],
        ("google.net", "A"): ["5.6.7.8"]}))
    r = await brand.lookalikes("google.com")
    assert [x["domain"] for x in r["results"]] == ["gogle.com", "google.net"]
    assert r["results"][0]["risk"] == "high"


# ---------- username ----------
@pytest.mark.parametrize("check,status,body,expected", [
    ("status", 200, "", "found"), ("status", 404, "", "not_found"), ("status", 429, "", "unknown"),
    ("json_null", 200, "null", "not_found"), ("json_null", 200, '{"id":"x"}', "found"),
    ("absent:[]", 200, "[]", "not_found"), ("absent:[]", 200, '[{"id":1}]', "found"),
])
def test_username_interpret(check, status, body, expected):
    assert username.interpret(check, status, body) == expected


@respx.mock
async def test_username_scan():
    respx.get("https://api.github.com/users/alice").mock(return_value=httpx.Response(200, json={}))
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))
    r = (await username.scan("alice"))["footprint"]["data"]
    gh = next(x for x in r["results"] if x["site"] == "GitHub")
    assert gh["status"] == "found" and r["found"] >= 1
