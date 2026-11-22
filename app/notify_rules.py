"""User-defined notification rules per tenant (the "notification creation tool").

A rule matches an incident when every condition that is set holds: minimum severity, minimum urgency, any of the
listed domains, any alert rule id starting with one of the prefixes, a keyword in the title, real data only.
A match writes an in-app notification (shown under the bell) and can also push to the channels the server has
configured (Teams / LINE / Slack / webhook / email). Each rule fires at most once per incident per severity level.
"""
import time

from app import soc_store
from app.workspace import urgency

SEV = ["info", "low", "medium", "high", "critical"]
CHANNELS = ("in_app", "teams", "line", "slack", "webhook", "email")
_cache: dict[str, list[dict]] = {}


def rules(tenant: str) -> list[dict]:
    if tenant not in _cache:
        _cache[tenant] = soc_store.list_notify_rules(tenant)
    return _cache[tenant]


def invalidate(tenant: str) -> None:
    _cache.pop(tenant, None)


def validate(r: dict) -> list[str]:
    errs = []
    if not (r.get("name") or "").strip():
        errs.append("ต้องมีชื่อกฎ")
    if r.get("min_severity") and r["min_severity"] not in SEV:
        errs.append("min_severity ไม่ถูกต้อง")
    if not 0 <= int(r.get("min_urgency") or 0) <= 100:
        errs.append("min_urgency ต้องอยู่ระหว่าง 0–100")
    bad = [c for c in r.get("channels") or [] if c not in CHANNELS]
    if bad:
        errs.append(f"ช่องทางไม่รู้จัก: {', '.join(bad)}")
    if not r.get("channels"):
        errs.append("ต้องเลือกอย่างน้อย 1 ช่องทาง")
    return errs


def incident_urgency(inc: dict) -> int:
    alerts = inc.get("alerts", [])
    return urgency(inc.get("severity", "info"), len(alerts), any(a.get("cti_match") for a in alerts),
                   bool(inc.get("coordinated")))


def matches(rule: dict, inc: dict) -> bool:
    if not rule.get("enabled", True):
        return False
    if rule.get("real_only", True) and not inc.get("real"):
        return False
    if SEV.index(inc.get("severity", "info")) < SEV.index(rule.get("min_severity") or "info"):
        return False
    if incident_urgency(inc) < int(rule.get("min_urgency") or 0):
        return False
    doms = rule.get("domains") or []
    if doms and not set(doms) & set(inc.get("domains", [])):
        return False
    prefixes = [p.upper() for p in rule.get("rule_prefixes") or [] if p]
    if prefixes and not any((a.get("rule") or "").upper().startswith(tuple(prefixes)) for a in inc.get("alerts", [])):
        return False
    kw = (rule.get("keyword") or "").lower().strip()
    if kw and kw not in " ".join([inc.get("title") or ""] + [a.get("title") or "" for a in inc.get("alerts", [])]).lower():
        return False
    return True


def evaluate(tenant: str, inc: dict, external=None, now: float | None = None) -> list[str]:
    """Run the tenant's rules on a changed incident. Returns the ids of rules that fired."""
    fired = []
    sev = SEV.index(inc.get("severity", "info"))
    done = inc.setdefault("rule_fired", {})
    for r in rules(tenant):
        if done.get(r["id"], -1) >= sev or not matches(r, inc):
            continue
        done[r["id"]] = sev
        fired.append(r["id"])
        if "in_app" in r["channels"]:
            soc_store.add_inbox({"ts": now or time.time(), "rule_id": r["id"], "rule": r["name"], "kind": "incident",
                                 "ref": inc["id"], "severity": inc.get("severity"), "title": inc.get("title"),
                                 "real": bool(inc.get("real")), "urgency": incident_urgency(inc)}, tenant)
        ext = [c for c in r["channels"] if c != "in_app"]
        if ext and external:
            external(inc, ext)
    return fired


def test_rule(rule: dict, incidents: list[dict]) -> list[dict]:
    """Which current incidents would this rule have matched (preview before saving)."""
    probe = {**rule, "enabled": True}
    return [{"id": i["id"], "title": i.get("title"), "severity": i.get("severity"), "urgency": incident_urgency(i),
             "real": bool(i.get("real"))} for i in incidents if matches(probe, i)][:50]
