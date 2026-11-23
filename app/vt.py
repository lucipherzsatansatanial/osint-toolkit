"""VirusTotal API v3 client: reputation look-ups for file hashes, URLs, domains and IP addresses.

Look-ups are GET requests (`/files/{hash}`, `/urls/{id}`, `/domains/{d}`, `/ip_addresses/{ip}`): nothing is
uploaded. Submitting a URL for a fresh scan (`POST /urls`) makes that URL visible to the VirusTotal community, so
the API layer only allows it with an explicit confirmation and a higher permission. File upload is deliberately
not offered: uploaded files can be downloaded by VirusTotal's premium customers, which is a data-leak and PDPA risk
for customer files.

Guards:
- private / internal indicators (RFC 1918 IPs, *.local, *.corp ...) are refused before any request leaves the server;
- a process-wide rate limiter keeps within the key's quota (public API: 4 requests/minute, 500/day by default);
- answers are cached (default 1 hour), so repeated look-ups of the same IOC cost nothing.
"""
import asyncio
import base64
import ipaddress
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app import intel
from app import config
from app.modules.common import http_client

BASE = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
KIND = {"ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}
PATH = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "file": "files"}
GUI_PATH = {"ip": "ip-address", "domain": "domain", "url": "url", "file": "file"}
INTERNAL_SUFFIXES = (".local", ".localdomain", ".internal", ".intranet", ".corp", ".lan", ".home", ".home.arpa",
                     ".localhost", ".test", ".invalid", ".example")
CACHE_MAX = 5000

_cache: "OrderedDict[tuple[str, str], tuple[float, dict]]" = OrderedDict()
_minute: deque = deque()
_day = {"date": "", "used": 0}
_lock = asyncio.Lock()


class VTError(Exception):
    def __init__(self, code: str, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.code, self.message, self.retry_after = code, message, retry_after


def enabled() -> bool:
    return bool(config.settings.vt_api_key)


def reset() -> None:  # tests
    _cache.clear(), _minute.clear()
    _day.update(date="", used=0)


def usage() -> dict:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    used = _day["used"] if _day["date"] == today else 0
    now = time.time()
    return {"enabled": enabled(), "per_minute": config.settings.vt_rate_per_min, "daily_quota": config.settings.vt_daily_quota,
            "used_today": used, "used_last_minute": sum(1 for t in _minute if now - t < 60), "cached": len(_cache)}


def _internal_host(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return not ip.is_global
    except ValueError:
        pass
    if "." not in host or host.endswith(INTERNAL_SUFFIXES) or host in ("localhost",):
        return True
    return any(host == s or host.endswith("." + s) for s in config.settings.vt_block_domains)


def target(value: str) -> tuple[str, str]:
    """-> (kind, normalised value); raises VTError for unsupported or internal indicators."""
    typ, v = intel.classify(value)
    kind = KIND.get(typ or "")
    if not kind:
        raise VTError("unsupported", "VirusTotal รองรับเฉพาะ hash (md5/sha1/sha256), URL, domain และ IP")
    if kind == "ip" and _internal_host(v):
        raise VTError("internal", "ไม่ส่ง IP ภายในองค์กร (private/reserved) ไปยัง VirusTotal")
    if kind == "domain" and _internal_host(v):
        raise VTError("internal", "ไม่ส่งชื่อโดเมนภายในองค์กรไปยัง VirusTotal")
    if kind == "url":
        parts = urlsplit(v)
        if _internal_host(parts.hostname or ""):
            raise VTError("internal", "ไม่ส่ง URL ของระบบภายในไปยัง VirusTotal")
        if parts.username or parts.password:
            raise VTError("internal", "URL มีชื่อผู้ใช้/รหัสผ่านฝังอยู่ — ไม่ส่งไปยัง VirusTotal")
    return kind, v


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def gui_link(kind: str, v: str) -> str:
    return f"{GUI}/{GUI_PATH[kind]}/{url_id(v) if kind == 'url' else v}"


async def _spend() -> None:
    """Reserve one request against the per-minute and per-day budget, or raise VTError('quota')."""
    async with _lock:
        now = time.time()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if _day["date"] != today:
            _day.update(date=today, used=0)
        while _minute and now - _minute[0] >= 60:
            _minute.popleft()
        if _day["used"] >= config.settings.vt_daily_quota:
            raise VTError("quota", f"ใช้โควตา VirusTotal ครบ {config.settings.vt_daily_quota} ครั้งของวันนี้แล้ว (UTC)")
        if len(_minute) >= config.settings.vt_rate_per_min:
            wait = int(60 - (now - _minute[0])) + 1
            raise VTError("quota", f"เกิน {config.settings.vt_rate_per_min} ครั้ง/นาที — ลองใหม่ใน {wait} วินาที", wait)
        _minute.append(now)
        _day["used"] += 1


async def _request(method: str, path: str, **kw) -> dict:
    await _spend()
    async with http_client(headers={"x-apikey": config.settings.vt_api_key, "accept": "application/json"}) as c:
        r = await c.request(method, BASE + path, **kw)
    if r.status_code == 404:
        raise VTError("not_found", "VirusTotal ยังไม่มีข้อมูลของค่านี้")
    if r.status_code in (401, 403):
        raise VTError("auth", "VT_API_KEY ไม่ถูกต้องหรือไม่มีสิทธิ์ใช้ endpoint นี้")
    if r.status_code == 429:
        raise VTError("quota", "VirusTotal แจ้งว่าใช้โควตาเกิน (429) — ลองใหม่ภายหลัง", 60)
    if r.status_code >= 400:
        raise VTError("error", f"VirusTotal ตอบ HTTP {r.status_code}")
    return r.json()


def _iso(ts) -> str | None:
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return None


def summarise(kind: str, value: str, data: dict) -> dict:
    a = (data.get("data") or {}).get("attributes") or {}
    stats = a.get("last_analysis_stats") or {}
    results = a.get("last_analysis_results") or {}
    flagged = sorted(((eng, r.get("result") or r.get("category")) for eng, r in results.items()
                      if r.get("category") in ("malicious", "suspicious")), key=lambda x: x[0].lower())
    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, int))
    verdict = "malicious" if mal >= 3 else "suspicious" if mal or sus else "clean" if total else "unknown"
    out = {"indicator": value, "kind": kind, "found": True, "verdict": verdict,
           "malicious": mal, "suspicious": sus, "harmless": int(stats.get("harmless", 0)),
           "undetected": int(stats.get("undetected", 0)), "engines": total,
           "reputation": a.get("reputation"), "last_analysis": _iso(a.get("last_analysis_date")),
           "tags": (a.get("tags") or [])[:10], "flagged_by": [{"engine": e, "result": r} for e, r in flagged[:12]],
           "link": gui_link(kind, value)}
    label = ((a.get("popular_threat_classification") or {}).get("suggested_threat_label"))
    if label:
        out["threat_label"] = label
    if kind == "file":
        out.update(name=a.get("meaningful_name"), type=a.get("type_description"), size=a.get("size"),
                   sha256=a.get("sha256"), first_seen=_iso(a.get("first_submission_date")))
    elif kind == "ip":
        out.update(as_owner=a.get("as_owner"), asn=a.get("asn"), country=a.get("country"), network=a.get("network"))
    elif kind == "domain":
        out.update(registrar=a.get("registrar"), created=_iso(a.get("creation_date")),
                   categories=sorted(set((a.get("categories") or {}).values()))[:6])
    elif kind == "url":
        out.update(final_url=a.get("last_final_url"), title=a.get("title"),
                   categories=sorted(set((a.get("categories") or {}).values()))[:6])
    return out


async def lookup(value: str) -> dict:
    """Reputation report for one indicator. Never raises: errors come back as {'error': code, 'message': ...}."""
    try:
        kind, v = target(value)
    except VTError as e:
        return {"indicator": value, "error": e.code, "message": e.message}
    if not enabled():
        return {"indicator": v, "kind": kind, "error": "disabled", "message": "ยังไม่ได้ตั้ง VT_API_KEY"}
    key = (kind, v.lower() if kind != "url" else v)
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < config.settings.vt_cache_ttl:
        _cache.move_to_end(key)
        return {**hit[1], "cached": True}
    try:
        res = summarise(kind, v, await _request("GET", f"/{PATH[kind]}/{url_id(v) if kind == 'url' else v}"))
    except VTError as e:
        if e.code != "not_found":
            return {"indicator": v, "kind": kind, "error": e.code, "message": e.message, "retry_after": e.retry_after}
        res = {"indicator": v, "kind": kind, "found": False, "verdict": "unknown", "message": e.message,
               "link": gui_link(kind, v)}
    except Exception as e:  # network failure: report, do not cache
        return {"indicator": v, "kind": kind, "error": "network", "message": f"เชื่อมต่อ VirusTotal ไม่ได้ ({type(e).__name__})"}
    _cache[key] = (time.time(), res)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)
    return {**res, "cached": False}


async def lookup_many(values: list[str]) -> list[dict]:
    """Sequential on purpose: the quota is per minute, and the order of results matches the input."""
    return [await lookup(v) for v in values]


async def submit_url(url: str) -> dict:
    """Ask VirusTotal to (re)scan a URL. The URL becomes visible to the VirusTotal community."""
    kind, v = target(url)
    if kind != "url":
        raise VTError("unsupported", "ส่งสแกนได้เฉพาะ URL (http/https)")
    if not enabled():
        raise VTError("disabled", "ยังไม่ได้ตั้ง VT_API_KEY")
    j = await _request("POST", "/urls", data={"url": v})
    _cache.pop(("url", v), None)
    return {"indicator": v, "analysis_id": (j.get("data") or {}).get("id"), "link": gui_link("url", v),
            "message": "ส่งให้ VirusTotal สแกนแล้ว — ผลจะพร้อมภายในไม่กี่นาที แล้วค้นซ้ำเพื่อดูผล"}


async def osint_check(value: str) -> dict:
    """VirusTotal section for the OSINT Toolkit's IP / domain scans."""
    if not enabled():
        return {"skipped": "Set VT_API_KEY to add VirusTotal reputation (virustotal.com API v3)"}
    return await lookup(value)
