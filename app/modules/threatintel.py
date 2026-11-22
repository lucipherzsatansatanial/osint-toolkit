"""Live Cyber Threat Intelligence from free public feeds (no API key).

Feeds (fixed URLs, never user-supplied, so no SSRF surface):
- CISA Known Exploited Vulnerabilities (KEV) catalog
- abuse.ch Feodo Tracker: botnet C2 servers (Emotet/QakBot/Dridex/...)
- abuse.ch ThreatFox: recent IOCs (export may need an Auth-Key in future; failure is non-fatal)

Results are cached in memory for CACHE_TTL seconds; a failed feed keeps its last good copy.
"""
import asyncio
import time
from typing import Any

from app.modules.common import http_client

FEEDS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "threatfox": "https://threatfox.abuse.ch/export/json/recent/",
}
CACHE_TTL = 900
TOP = 30

_cache: dict[str, dict[str, Any]] = {}
_lock = asyncio.Lock()


def parse_kev(raw: dict) -> dict:
    vulns = raw.get("vulnerabilities") or []
    vulns = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
    items = [{
        "cve": v.get("cveID"), "vendor": v.get("vendorProject"), "product": v.get("product"),
        "name": v.get("vulnerabilityName"), "date_added": v.get("dateAdded"), "due": v.get("dueDate"),
        "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
    } for v in vulns[:TOP]]
    return {"total": len(vulns), "catalog_version": raw.get("catalogVersion"),
            "ransomware_linked": sum(1 for v in vulns
                                     if (v.get("knownRansomwareCampaignUse") or "").lower() == "known"),
            "items": items}


def parse_feodo(raw: list) -> dict:
    rows = raw if isinstance(raw, list) else []
    rows = sorted(rows, key=lambda r: r.get("last_online") or r.get("first_seen") or "", reverse=True)
    by_malware: dict[str, int] = {}
    for r in rows:
        m = r.get("malware") or "unknown"
        by_malware[m] = by_malware.get(m, 0) + 1
    items = [{
        "ip": r.get("ip_address"), "port": r.get("port"), "malware": r.get("malware"),
        "status": r.get("status"), "country": r.get("country"), "as_name": r.get("as_name"),
        "first_seen": r.get("first_seen"), "last_online": r.get("last_online"),
    } for r in rows[:TOP]]
    return {"total": len(rows), "online": sum(1 for r in rows if r.get("status") == "online"),
            "by_malware": dict(sorted(by_malware.items(), key=lambda kv: -kv[1])), "items": items}


def parse_threatfox(raw: dict) -> dict:
    flat: list[dict] = []
    if isinstance(raw, dict):
        for entries in raw.values():
            if isinstance(entries, list):
                flat.extend(e for e in entries if isinstance(e, dict))
    flat.sort(key=lambda e: e.get("first_seen_utc") or "", reverse=True)
    by_type: dict[str, int] = {}
    for e in flat:
        t = e.get("threat_type") or "unknown"
        by_type[t] = by_type.get(t, 0) + 1
    items = [{
        "ioc": e.get("ioc_value"), "type": e.get("ioc_type"), "threat": e.get("threat_type"),
        "malware": e.get("malware_printable"), "confidence": e.get("confidence_level"),
        "first_seen": e.get("first_seen_utc"),
    } for e in flat[:TOP]]
    return {"total": len(flat), "by_threat_type": by_type, "items": items}


PARSERS = {"kev": parse_kev, "feodo": parse_feodo, "threatfox": parse_threatfox}


async def _fetch(client, name: str) -> dict:
    t0 = time.time()
    try:
        r = await client.get(FEEDS[name])
        r.raise_for_status()
        data = PARSERS[name](r.json())
        return {"ok": True, "fetched_at": t0, "source": FEEDS[name], "data": data}
    except Exception as e:  # noqa: BLE001 - one feed failing must not sink the dashboard
        prev = _cache.get(name)
        out = {"ok": False, "fetched_at": t0, "source": FEEDS[name], "error": f"{type(e).__name__}: {e}"}
        if prev and prev.get("data"):
            out.update(data=prev["data"], stale=True)
        return out


async def get_all(force: bool = False) -> dict[str, dict]:
    async with _lock:
        now = time.time()
        due = [n for n in FEEDS if force or now - _cache.get(n, {}).get("fetched_at", 0) > CACHE_TTL]
        if due:
            async with http_client(follow_redirects=True) as client:
                results = await asyncio.gather(*(_fetch(client, n) for n in due))
            _cache.update(zip(due, results))
        return {n: _cache[n] for n in FEEDS}


def c2_ips() -> list[str]:
    feodo = (_cache.get("feodo") or {}).get("data") or {}
    return [i["ip"] for i in feodo.get("items", []) if i.get("ip")]


def kev_cves() -> list[dict]:
    kev = (_cache.get("kev") or {}).get("data") or {}
    return kev.get("items", [])
