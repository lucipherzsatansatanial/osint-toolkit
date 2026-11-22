"""Live Cyber Threat Intelligence from free public feeds (no API key).

Feeds (fixed URLs, never user-supplied, so no SSRF surface):
- CISA Known Exploited Vulnerabilities (KEV) catalog
- abuse.ch Feodo Tracker: botnet C2 servers (Emotet/QakBot/Dridex/...)
- abuse.ch ThreatFox: recent IOCs (export may need an Auth-Key in future; failure is non-fatal)
- ThreatDefence agentic-attack-detections (MIT): indicators for offensive AI-agent frameworks
  (ARTEX/AntiFox, Cairn, PentAGI, HexStrike, CyberStrikeAI, Strix, Hermes Agent, Agent Zero)

Results are cached in memory for CACHE_TTL seconds; a failed feed keeps its last good copy.
"""
import asyncio
import csv
import io
import time
from datetime import date
from typing import Any

from app.modules.common import http_client

FEEDS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "threatfox": "https://threatfox.abuse.ch/export/json/recent/",
    "agentic": "https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main/iocs/indicators.csv",
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
    index = {(v.get("cveID") or "").upper(): {
        "cve": v.get("cveID"), "vendor": v.get("vendorProject"), "product": v.get("product"),
        "name": v.get("vulnerabilityName"), "date_added": v.get("dateAdded"), "due": v.get("dueDate"),
        "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
        "description": (v.get("shortDescription") or "")[:400]} for v in vulns if v.get("cveID")}
    return {"total": len(vulns), "catalog_version": raw.get("catalogVersion"), "index": index,
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
    index = {r["ip_address"]: {"ip": r["ip_address"], "port": r.get("port"), "malware": r.get("malware"),
                                "status": r.get("status"), "country": r.get("country"), "as_name": r.get("as_name"),
                                "first_seen": r.get("first_seen"), "last_online": r.get("last_online")}
             for r in rows if r.get("ip_address")}
    return {"total": len(rows), "online": sum(1 for r in rows if r.get("status") == "online"), "index": index,
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
    index = {}
    for e in flat:
        v = str(e.get("ioc_value") or "").lower()
        if v:
            index.setdefault(v, {"ioc": e.get("ioc_value"), "type": e.get("ioc_type"), "threat": e.get("threat_type"),
                                 "malware": e.get("malware_printable"), "confidence": e.get("confidence_level"),
                                 "first_seen": e.get("first_seen_utc"), "tags": e.get("tags")})
    return {"total": len(flat), "by_threat_type": by_type, "items": items, "index": index}


def parse_agentic(text: str, today: date | None = None) -> dict:
    """CSV columns: type,value,confidence,context,actor,source,source_url,reported,review_by,framework.
    Rows past their review_by date are dropped (addresses age out; the maintainers set 180 days)."""
    today = today or date.today()
    rows, expired = [], 0
    for r in csv.DictReader(io.StringIO(text)):
        if not r.get("type") or not r.get("value"):
            continue
        rb = (r.get("review_by") or "").strip()
        try:
            if rb and date.fromisoformat(rb) < today:
                expired += 1
                continue
        except ValueError:
            pass
        rows.append({k: (r.get(k) or "").strip() for k in
                     ("type", "value", "confidence", "context", "actor", "source", "source_url", "reported",
                      "framework")})
    by_fw: dict[str, int] = {}
    for r in rows:
        for fw in r["framework"].split():
            by_fw[fw] = by_fw.get(fw, 0) + 1
    recent = sorted(rows, key=lambda r: r["reported"], reverse=True)
    items = [{k: r[k] for k in ("type", "value", "confidence", "framework", "source", "source_url", "reported")}
             | {"context": r["context"][:200]} for r in recent if r["confidence"] == "high"][:TOP]
    return {"total": len(rows), "expired": expired, "by_framework": by_fw, "items": items, "rows": rows}


PARSERS = {"kev": parse_kev, "feodo": parse_feodo, "threatfox": parse_threatfox, "agentic": parse_agentic}
TEXT_FEEDS = {"agentic"}


async def _fetch(client, name: str) -> dict:
    t0 = time.time()
    try:
        r = await client.get(FEEDS[name])
        r.raise_for_status()
        data = PARSERS[name](r.text if name in TEXT_FEEDS else r.json())
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


def public(feeds: dict[str, dict]) -> dict[str, dict]:
    """Strip bulky internal fields (full indicator rows) before sending to the browser."""
    out = {}
    for n, f in feeds.items():
        data = f.get("data")
        out[n] = {**f, "data": {k: v for k, v in data.items() if k not in ("rows", "index")}} if data else f
    return out


def agentic_index() -> list[dict]:
    return ((_cache.get("agentic") or {}).get("data") or {}).get("rows") or []


def c2_ips() -> list[str]:
    feodo = (_cache.get("feodo") or {}).get("data") or {}
    return [i["ip"] for i in feodo.get("items", []) if i.get("ip")]


def kev_cves() -> list[dict]:
    kev = (_cache.get("kev") or {}).get("data") or {}
    return kev.get("items", [])


def feed_index(name: str) -> dict:
    return ((_cache.get(name) or {}).get("data") or {}).get("index") or {}
