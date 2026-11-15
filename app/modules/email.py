"""Email intelligence: mail-security posture of the domain, Gravatar, breach exposure (HIBP)."""
import hashlib
from urllib.parse import quote

from app.config import settings
from app.modules.common import dns_query, http_client, run_checks

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]


def _strip(txt: str) -> str:
    return txt.replace('" "', "").strip('"')


def assess_spf(records: list[str]) -> dict:
    spf = [_strip(r) for r in records if _strip(r).lower().startswith("v=spf1")]
    if not spf:
        return {"present": False, "risk": "high", "note": "No SPF record — domain can be spoofed"}
    if len(spf) > 1:
        return {"present": True, "record": spf, "risk": "high", "note": "Multiple SPF records (invalid)"}
    rec = spf[0]
    if "+all" in rec:
        risk, note = "high", "+all allows any sender"
    elif "?all" in rec:
        risk, note = "medium", "?all is neutral (not enforced)"
    elif "~all" in rec:
        risk, note = "low", "~all softfail"
    elif "-all" in rec:
        risk, note = "none", "-all hardfail (strict)"
    else:
        risk, note = "medium", "No 'all' mechanism"
    return {"present": True, "record": rec, "risk": risk, "note": note}


def assess_dmarc(records: list[str]) -> dict:
    rec = next((_strip(r) for r in records if _strip(r).lower().startswith("v=dmarc1")), None)
    if not rec:
        return {"present": False, "risk": "high", "note": "No DMARC — spoofed mail will not be rejected"}
    tags = dict(t.strip().split("=", 1) for t in rec.split(";") if "=" in t)
    policy = tags.get("p", "none").lower()
    risk = {"reject": "none", "quarantine": "low"}.get(policy, "medium")
    return {"present": True, "record": rec, "policy": policy, "rua": tags.get("rua"), "risk": risk}


async def mail_security(domain: str) -> dict:
    mx = await dns_query(domain, "MX")
    spf = assess_spf(await dns_query(domain, "TXT"))
    dmarc = assess_dmarc(await dns_query(f"_dmarc.{domain}", "TXT"))
    dkim = []
    for sel in COMMON_DKIM_SELECTORS:
        if await dns_query(f"{sel}._domainkey.{domain}", "TXT"):
            dkim.append(sel)
    return {
        "mx": sorted(mx),
        "accepts_mail": bool(mx),
        "spf": spf,
        "dmarc": dmarc,
        "dkim_selectors_found": dkim,
        "dkim_note": "Only common selectors are probed; absence is not proof DKIM is off",
    }


async def gravatar(email: str) -> dict:
    h = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    async with http_client() as c:
        r = await c.get(f"https://gravatar.com/avatar/{h}?d=404&s=80")
    return {"exists": r.status_code == 200,
            "avatar_url": f"https://gravatar.com/avatar/{h}?s=200" if r.status_code == 200 else None}


async def hibp_breaches(email: str) -> dict:
    if not settings.hibp_api_key:
        return {"skipped": "Set HIBP_API_KEY to enable breach lookup (haveibeenpwned.com/API/Key)"}
    async with http_client(headers={"hibp-api-key": settings.hibp_api_key}) as c:
        r = await c.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                        params={"truncateResponse": "false"})
    if r.status_code == 404:
        return {"breached": False, "breaches": []}
    r.raise_for_status()
    rows = r.json()
    return {
        "breached": True,
        "count": len(rows),
        "breaches": [{"name": b.get("Name"), "domain": b.get("Domain"), "date": b.get("BreachDate"),
                      "data_classes": b.get("DataClasses", [])} for b in rows],
    }


async def scan(email: str) -> dict:
    domain = email.rsplit("@", 1)[1]
    return await run_checks({
        "mail_security": lambda: mail_security(domain),
        "gravatar": lambda: gravatar(email),
        "breaches": lambda: hibp_breaches(email),
    })
