"""Threat Map: where the infrastructure behind this tenant's alerts sits, and what is being hit.

Everything is computed from data the platform already holds — nothing is invented:
- origin country of an alert = `src_country` on the event (set by the simulator for demo data, or by the log shipper
  for real data, e.g. ECS source.geo.country_iso_code), else the country abuse.ch Feodo Tracker lists for the alert's
  remote IP. Alerts with neither are counted as "unknown", never guessed;
- the country is where the attacking *infrastructure* is (server, proxy, C2), not who the attacker is;
- the global panel is the abuse.ch Feodo Tracker botnet-C2 list by hosting country.
"""
import re
from collections import Counter

CC = re.compile(r"^[A-Z]{2}$")
DAY = 86400


def _cc(v) -> str | None:
    v = str(v or "").strip().upper()
    return v if CC.match(v) else None


def origin(e: dict, feodo: dict) -> str | None:
    cc = _cc(e.get("src_country"))
    if cc:
        return cc
    for k in ("remote_ip", "indicator", "src_ip"):
        hit = feodo.get(str(e.get(k) or ""))
        if hit and _cc(hit.get("country")):
            return _cc(hit["country"])
    return None


def _top(c: Counter, n: int) -> list[dict]:
    return [{"country": k, "count": v} for k, v in c.most_common(n)]


def build(events: list[dict], incidents: list[dict], feodo: dict, indicators: list[dict], home: str,
          now: float, days: int = 7) -> dict:
    """events: alert events of the last 30 days (any order); incidents: the tenant's incidents."""
    start = now - days * DAY
    win = [e for e in events if (e.get("ts") or 0) >= start and e.get("severity") != "info"]
    origins, real_origins, unknown = Counter(), Counter(), 0
    for e in win:
        cc = origin(e, feodo)
        if not cc:
            unknown += 1
            continue
        origins[cc] += 1
        if e.get("simulated") is False:
            real_origins[cc] += 1
    arcs = [{"from": k, "count": v} for k, v in origins.most_common(12) if k != home][:10]

    inc_win = [i for i in incidents if (i.get("first_ts") or 0) >= start]
    trend = [0] * 30
    for i in incidents:
        age = int((now - (i.get("first_ts") or 0)) // DAY)
        if 0 <= age < 30:
            trend[29 - age] += 1

    tactics = Counter(e.get("tactic") for e in win if e.get("tactic"))
    total_t = sum(tactics.values())
    categories = [{"name": k, "count": v, "share": round(v / total_t, 4)} for k, v in tactics.most_common(5)] if total_t else []

    targets = Counter(e.get("host") for e in win if e.get("host"))
    crit_by_host = {}
    for e in win:
        if e.get("host") and e.get("severity") in ("critical", "high"):
            crit_by_host[e["host"]] = crit_by_host.get(e["host"], 0) + 1

    infra = Counter(_cc(r.get("country")) for r in feodo.values() if _cc(r.get("country")))
    by_type = Counter(i.get("type") for i in indicators if i.get("type") and i.get("type") != "cve")
    unique = {str(i.get("value", "")).lower() for i in indicators if i.get("type") != "cve"}

    return {"generated_at": now, "days": days, "home": home,
            "incidents": len(inc_win), "alerts": len(win), "ioc_unique": len(unique),
            "trend": trend, "origins": _top(origins, 10), "real_origins": _top(real_origins, 10),
            "unknown_origin": unknown, "located": sum(origins.values()), "arcs": arcs,
            "targets": [{"host": h, "alerts": n, "high": crit_by_host.get(h, 0)} for h, n in targets.most_common(8)],
            "categories": categories,
            "infra": {"source": "abuse.ch Feodo Tracker (botnet C2)", "total": sum(infra.values()), "top": _top(infra, 5)},
            "ioc_types": [{"type": k, "count": v} for k, v in by_type.most_common(5)],
            "simulated_share": round(sum(1 for e in win if e.get("simulated") is not False) / len(win), 3) if win else 0}
