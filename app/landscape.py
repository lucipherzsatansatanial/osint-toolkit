"""Threat landscape: trends computed from REAL CTI feeds (ThreatFox, CISA KEV, Feodo) and from the tenant's own alerts.

Nothing here is a global telemetry claim: feed trends describe what the public feed published, and alert trends
describe this tenant's alerts only (simulated alerts are labelled by the caller).
"""
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

from app.workspace import TECHNIQUES


def _day(s: str | None) -> str | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace(" UTC", "").replace("Z", "")[:19]).date().isoformat()
    except ValueError:
        return str(s)[:10] if len(str(s)) >= 10 else None


def malware_trend(threatfox_index: dict, top: int = 5) -> dict:
    """IOCs per malware family per day, from the ThreatFox 'recent' export (covers only the last few days)."""
    per = defaultdict(Counter)
    total = Counter()
    for e in threatfox_index.values():
        m, d = e.get("malware") or "unknown", _day(e.get("first_seen"))
        if d:
            per[m][d] += 1
            total[m] += 1
    days = sorted({d for c in per.values() for d in c})
    fams = [m for m, _ in total.most_common(top)]
    return {"days": days, "series": [{"name": m, "points": [per[m].get(d, 0) for d in days], "total": total[m]}
                                     for m in fams], "source": "abuse.ch ThreatFox (recent export)"}


def kev_trend(kev_index: dict, weeks: int = 12, today: date | None = None) -> dict:
    """CISA KEV additions per ISO week (all vendors) plus the most frequent vendors in that period."""
    today = today or datetime.now(timezone.utc).date()
    start = today - timedelta(weeks=weeks)
    buckets = Counter()
    vendors = Counter()
    ransomware = 0
    for v in kev_index.values():
        d = _day(v.get("date_added"))
        try:
            dd = date.fromisoformat(d) if d else None
        except ValueError:
            dd = None
        if not dd or dd < start or dd > today:
            continue
        monday = dd - timedelta(days=dd.weekday())
        buckets[monday.isoformat()] += 1
        vendors[v.get("vendor") or "?"] += 1
        ransomware += bool(v.get("ransomware"))
    first = start - timedelta(days=start.weekday())
    labels = [(first + timedelta(weeks=i)).isoformat() for i in range(weeks + 1)]
    return {"weeks": labels, "added": [buckets.get(w, 0) for w in labels], "total": sum(buckets.values()),
            "ransomware": ransomware, "top_vendors": [{"vendor": k, "cves": n} for k, n in vendors.most_common(8)],
            "source": "CISA Known Exploited Vulnerabilities"}


def latest_kev(kev_index: dict, n: int = 6) -> list[dict]:
    rows = sorted(kev_index.values(), key=lambda v: v.get("date_added") or "", reverse=True)[:n]
    return [{"cve": v["cve"], "title": v.get("name"), "vendor": v.get("vendor"), "product": v.get("product"),
             "date": v.get("date_added"), "ransomware": v.get("ransomware"),
             "url": f"https://nvd.nist.gov/vuln/detail/{v['cve']}"} for v in rows]


def technique_trend(events: list[dict], now: float, hours: int = 24, buckets: int = 12, top: int = 5) -> dict:
    """This tenant's alerts per MITRE technique over time."""
    span = hours * 3600
    size = span / buckets
    start = now - span
    per = defaultdict(lambda: [0] * buckets)
    total = Counter()
    for e in events:
        t = e.get("technique")
        if not t or t == "—" or e["ts"] < start or e["ts"] > now:
            continue
        i = min(buckets - 1, int((e["ts"] - start) // size))
        per[t][i] += 1
        total[t] += 1
    return {"buckets": [start + size * (i + 1) for i in range(buckets)],
            "series": [{"technique": t, "name": TECHNIQUES.get(t, t), "points": per[t], "total": n}
                       for t, n in total.most_common(top)]}


def threat_of(e: dict) -> str | None:
    """Best label for the threat behind an alert: offensive-AI framework, CTI malware family, KEV CVE."""
    if e.get("framework"):
        return e["framework"]
    if e.get("malware"):
        return e["malware"]
    if e.get("cve"):
        return e["cve"]
    if e.get("cti_match"):
        return e["cti_match"]
    return None


def threats_table(events: list[dict], now: float, threatfox_index: dict, kev_index: dict) -> list[dict]:
    """Threats observed in this tenant's alerts, with how many related IOCs the public feeds currently list."""
    tf_by_malware = Counter((e.get("malware") or "").lower() for e in threatfox_index.values())
    rows: dict[str, dict] = {}
    for e in events:
        name = threat_of(e)
        if not name:
            continue
        r = rows.setdefault(name, {"threat": name, "alerts": 0, "last_7d": 0, "hosts": set(), "last_ts": 0})
        r["alerts"] += 1
        r["last_7d"] += e["ts"] >= now - 7 * 86400
        r["hosts"].add(e.get("host"))
        r["last_ts"] = max(r["last_ts"], e["ts"])
    out = []
    for r in rows.values():
        key = r["threat"].lower()
        related = tf_by_malware.get(key, 0)
        ref = None
        if r["threat"].upper().startswith("CVE-"):
            related = 1 if r["threat"].upper() in kev_index else 0
            ref = f"https://nvd.nist.gov/vuln/detail/{r['threat'].upper()}"
        out.append({**r, "hosts": len(r["hosts"] - {None}), "related_iocs": related, "reference": ref})
    out.sort(key=lambda r: (-r["last_7d"], -r["alerts"]))
    return out[:20]
