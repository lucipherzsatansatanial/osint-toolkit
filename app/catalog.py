"""Rules catalog: every detection rule the platform runs, with per-tenant on/off, 7-day alert counts,
analyst-rejected (false-positive) counts, a quality score, MITRE coverage and exported query files."""
import re
from collections import Counter, defaultdict
from pathlib import Path

from app import agent_detect, offensive_ai
from app.workspace import TECHNIQUES

DETECTIONS = Path(__file__).resolve().parent.parent / "detections"
FORMAT = {".kql": "KQL (Sentinel/Defender)", ".spl": "SPL (Splunk)", ".yml": "Sigma"}
REJECTED = ("false_positive", "benign")


def _exports() -> dict[str, list[dict]]:
    out = defaultdict(list)
    if not DETECTIONS.is_dir():
        return out
    for p in sorted(DETECTIONS.rglob("*")):
        if p.suffix not in FORMAT:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rid in set(re.findall(r"\b(?:OAI|AGT)-\d{3}\b", text)):
            out[rid].append({"file": str(p.relative_to(DETECTIONS.parent)), "format": FORMAT[p.suffix]})
    return out


_EXPORTS = None


def builtin_rules() -> list[dict]:
    global _EXPORTS
    if _EXPORTS is None:
        _EXPORTS = _exports()
    rows = []
    for rules, kind in ((offensive_ai.RULES, "builtin"), (agent_detect.RULES, "builtin")):
        for rid, (title, sev, tech, tactic) in rules.items():
            rows.append({"id": rid, "title": title, "severity": sev, "technique": tech, "tactic": tactic,
                         "category": src_label(rid, kind), "source": "built-in", "exports": _EXPORTS.get(rid, [])})
    return rows


def src_label(rid: str, kind: str) -> str:
    return "Offensive-AI behaviour" if rid.startswith("OAI") else "AI-agent policy" if rid.startswith("AGT") else "Custom"


def catalog(custom: list[dict], disabled: set[str], events: list[dict], incidents: dict, now: float) -> dict:
    rules = builtin_rules() + [{"id": r["id"], "title": r.get("title"), "severity": r.get("severity"),
                                "technique": r.get("technique"), "tactic": r.get("tactic"), "category": "Custom",
                                "source": "custom", "status": r.get("status"), "exports": []} for r in custom]
    week = now - 7 * 86400
    total, rejected, last = Counter(), Counter(), {}
    for e in events:
        rid = e.get("rule")
        if not rid or e["ts"] < week:
            continue
        total[rid] += 1
        last[rid] = max(last.get(rid, 0), e["ts"])
        inc = incidents.get(e.get("incident_id")) if e.get("incident_id") else None
        if inc and (inc.get("verdict") in REJECTED or inc.get("status") == "false_positive"):
            rejected[rid] += 1
    out = []
    for r in rules:
        rid = r["id"]
        enabled = rid not in disabled and (r["source"] != "custom" or r.get("status") == "enabled")
        n, rej = total[rid], rejected[rid]
        out.append({**r, "enabled": enabled, "alerts_7d": n, "rejected_7d": rej, "last_alert": last.get(rid),
                    "quality": None if n == 0 else round(100 * (n - rej) / n),
                    "technique_name": TECHNIQUES.get(r.get("technique") or "", r.get("technique"))})
    heat = Counter()
    covered = defaultdict(set)
    for r in out:
        t = r.get("technique")
        if t and t != "—":
            covered[r.get("tactic") or "?"].add(t)
            heat[t] += r["alerts_7d"]
    return {"rules": out,
            "summary": {"total": len(out), "enabled": sum(r["enabled"] for r in out),
                        "custom": sum(r["source"] == "custom" for r in out),
                        "alerts_7d": sum(r["alerts_7d"] for r in out),
                        "rejected_7d": sum(r["rejected_7d"] for r in out)},
            "mitre": [{"tactic": tac, "techniques": [{"id": t, "name": TECHNIQUES.get(t, t), "alerts_7d": heat[t]}
                                                     for t in sorted(ts)]} for tac, ts in covered.items()]}
