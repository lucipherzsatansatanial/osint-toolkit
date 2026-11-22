"""Events explorer (raw telemetry search + histogram) and the full alerts list (filters, sort, paging)."""
from app import workspace


def _s(v, n: int = 160) -> str:
    v = "" if v is None else str(v)
    return v if len(v) <= n else v[: n - 1] + "…"


def describe(r: dict) -> str:
    """One human-readable line per raw record, like a SIEM's event description column."""
    k = r.get("kind")
    host = r.get("host") or r.get("dest_host") or "?"
    if r.get("agent"):
        base = f"agent {r['agent']} ({k})"
        if k == "tool_call":
            return f"{base} called {_s(r.get('tool'), 60)} {_s(r.get('args'), 100)} → {r.get('decision') or '?'}"
        if k == "network":
            return f"{base} connected to {_s(r.get('dest') or r.get('ip'), 80)}:{r.get('port') or ''} ({r.get('bytes_out') or 0} B out)"
        if k == "process":
            return f"{base} spawned {_s(r.get('image'), 60)} {_s(r.get('cmdline'), 100)} on {host}"
        return f"{base}: {_s(r.get('summary') or r.get('snippet') or r.get('action'), 140)}"
    if k == "process":
        return f"{host} · {r.get('user') or '?'} ran {_s(r.get('image'), 60)} {_s(r.get('cmdline'), 110)}"
    if k == "http":
        return (f"{r.get('src_ip') or '?'} {r.get('method') or 'GET'} {_s(r.get('dst_host'), 60)}{_s(r.get('uri'), 80)}"
                f" → {r.get('status') or '-'}" + (f" ({_s(r.get('ua'), 40)})" if r.get("ua") else ""))
    if k == "net":
        return f"{host} connected to {r.get('dest_ip') or r.get('dest') or '?'}:{r.get('port') or ''} ({r.get('bytes') or 0} B)"
    if k == "logon":
        return (f"{r.get('user') or '?'} logged on to {r.get('dest_host') or host} from "
                f"{r.get('src_host') or r.get('src_ip') or '?'} (type {r.get('logon_type') or '-'}, event {r.get('event_id') or '-'})")
    if k == "db":
        return f"{r.get('user') or '?'}@{r.get('client_ip') or r.get('client_host') or '?'} on {r.get('db') or host}: {_s(r.get('statement'), 100)} ({r.get('rows') or 0} rows)"
    if k == "dlp":
        return f"DLP {r.get('action') or '?'}: {r.get('user') or '?'} → {_s(r.get('dest'), 60)} via {r.get('channel') or '?'} ({r.get('classification') or '-'})"
    return _s(r.get("summary") or str({x: y for x, y in r.items() if x not in ("ts",)}), 200)


def match(rec: dict, desc: str, query: str) -> bool:
    """`field:value` (substring), `-field:value` negates, bare words search the description."""
    for term in query.split():
        neg = term.startswith("-")
        term = term[1:] if neg else term
        if not term:
            continue
        if ":" in term:
            f, v = term.split(":", 1)
            got = v.lower() in str(rec.get(f, "")).lower()
        else:
            got = term.lower() in desc.lower()
        if got == neg:
            return False
    return True


def explore(records: list[dict], query: str, start: float, end: float, buckets: int = 60, limit: int = 200) -> dict:
    size = max(1.0, (end - start) / buckets)
    hist = [{"ts": start + size * i, "real": 0, "simulated": 0} for i in range(buckets)]
    rows = []
    total = 0
    kinds: dict[str, int] = {}
    for r in records:
        ts = r.get("ts") or 0
        if ts < start or ts > end:
            continue
        d = describe(r)
        if query and not match(r, d, query):
            continue
        total += 1
        kinds[r.get("kind") or "?"] = kinds.get(r.get("kind") or "?", 0) + 1
        hist[min(buckets - 1, int((ts - start) // size))]["simulated" if r.get("simulated", True) is not False else "real"] += 1
        rows.append((ts, r, d))
    rows.sort(key=lambda x: -x[0])
    return {"total": total, "bucket_sec": size, "histogram": hist, "by_kind": kinds,
            "rows": [{"ts": ts, "kind": r.get("kind"), "host": r.get("host") or r.get("dest_host"),
                      "real": r.get("simulated") is False, "source": r.get("_source"), "description": d,
                      "record": {k: v for k, v in r.items() if not k.startswith("_")}} for ts, r, d in rows[:limit]]}


def detection_type(a: dict) -> str:
    rule = a.get("rule") or ""
    if rule.startswith("CUS-"):
        return "Custom rule"
    if rule.startswith("OAI-"):
        return "Offensive-AI behaviour"
    if rule.startswith("AGT-"):
        return "AI-agent policy"
    if a.get("cti"):
        return "CTI / IOC"
    return "Built-in EDR/XDR"


VERDICT = {"false_positive": "false_positive", "resolved": "true_positive", "closed": "true_positive"}


def alerts_page(events: list[dict], incidents: dict, status: str = "", severity: str = "", q: str = "",
                real_only: bool = False, sort: str = "recent", page: int = 1, size: int = 25, states: dict | None = None) -> dict:
    items = workspace.alert_summary(events, incidents, limit=100000, states=states)
    tact = {}
    for e in events:
        tact.setdefault((e.get("title"), e.get("host")), (e.get("tactic"), e.get("framework") or e.get("malware") or e.get("cve")))
    for a in items:
        inc = incidents.get(a["incident_id"]) if a["incident_id"] else None
        a["verdict"] = (inc or {}).get("verdict") or (a.get("alert_state") or {}).get("verdict") or VERDICT.get(a["status"])
        a["detection_type"] = detection_type(a)
        a["type"], threat = tact.get((a["title"], a["host"]), (None, None))
        a["threats"] = [t for t in (threat, a["cti"] and "CTI match") if t]
    if status:
        items = [a for a in items if a["status"] in status.split(",")]
    if severity:
        items = [a for a in items if a["severity"] in severity.split(",")]
    if real_only:
        items = [a for a in items if a["real"]]
    if q:
        ql = q.lower()
        items = [a for a in items if ql in " ".join(str(a.get(k) or "") for k in
                                                     ("title", "host", "rule", "technique", "type", "assignee")).lower()]
    key = {"recent": lambda a: -a["last_ts"], "urgency": lambda a: (-a["urgency"], -a["last_ts"]),
           "occurrences": lambda a: (-a["occurrences"], -a["last_ts"])}.get(sort, lambda a: -a["last_ts"])
    items.sort(key=key)
    size = max(5, min(size, 100))
    pages = max(1, -(-len(items) // size))
    page = max(1, min(page, pages))
    return {"total": len(items), "page": page, "pages": pages, "size": size,
            "items": items[(page - 1) * size: page * size]}
