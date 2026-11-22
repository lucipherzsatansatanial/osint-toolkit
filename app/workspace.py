"""Analyst workspace: tasks, alert summary with urgency, data-source and threat statistics, notifications."""
import time
from collections import Counter, defaultdict

SEV_BASE = {"critical": 85, "high": 70, "medium": 45, "low": 20, "info": 5}
TASK_STATUSES = ("pending", "awaiting_input", "in_progress", "completed", "cancelled")
TASK_TH = {"pending": "รอดำเนินการ", "awaiting_input": "รอข้อมูล", "in_progress": "กำลังทำ",
           "completed": "เสร็จแล้ว", "cancelled": "ยกเลิก"}

# MITRE ATT&CK / ATLAS names for techniques the platform's rules and simulator emit
TECHNIQUES = {
    "T1003.001": "OS Credential Dumping: LSASS Memory", "T1021": "Remote Services",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares", "T1046": "Network Service Discovery",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1071.001": "Application Layer Protocol: Web Protocols", "T1071.004": "Application Layer Protocol: DNS",
    "T1078": "Valid Accounts", "T1090.002": "Proxy: External Proxy", "T1090.003": "Proxy: Multi-hop Proxy",
    "T1098": "Account Manipulation", "T1105": "Ingress Tool Transfer", "T1110": "Brute Force",
    "T1119": "Automated Collection", "T1190": "Exploit Public-Facing Application", "T1204": "User Execution",
    "T1204.002": "User Execution: Malicious File", "T1213": "Data from Information Repositories",
    "T1486": "Data Encrypted for Impact", "T1528": "Steal Application Access Token",
    "T1530": "Data from Cloud Storage", "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys",
    "T1552.001": "Unsecured Credentials: Credentials In Files", "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1566": "Phishing", "T1566.001": "Phishing: Spearphishing Attachment", "T1566.002": "Phishing: Spearphishing Link",
    "T1567": "Exfiltration Over Web Service", "T1567.002": "Exfiltration Over Web Service: to Cloud Storage",
    "T1588.002": "Obtain Capabilities: Tool", "T1595": "Active Scanning", "T1595.003": "Active Scanning: Wordlist Scanning",
    "T1621": "Multi-Factor Authentication Request Generation", "AML.T0051.001": "LLM Prompt Injection: Indirect",
}


def urgency(severity: str, occurrences: int, cti: bool, coordinated: bool) -> int:
    score = SEV_BASE.get(severity, 5) + min(10, max(0, occurrences - 1)) + (5 if cti else 0) + (5 if coordinated else 0)
    return min(100, score)


def alert_summary(events: list[dict], incidents: dict[int, dict], limit: int = 50) -> list[dict]:
    """Group alerts by (title, host) like a SIEM alert list: occurrences, first/last seen, urgency, case status."""
    groups: dict[tuple, dict] = {}
    for e in events:
        if e.get("severity") in ("info", "low") and not e.get("rule"):
            continue  # noise stays in the live stream only
        key = (e.get("title"), e.get("host"))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"title": e.get("title"), "host": e.get("host"), "severity": e.get("severity"),
                               "rule": e.get("rule"), "technique": e.get("technique"), "domain": e.get("domain"),
                               "occurrences": 0, "first_ts": e["ts"], "last_ts": e["ts"], "cti": False,
                               "incident_id": None, "real": e.get("simulated") is False}
        g["occurrences"] += 1
        g["first_ts"], g["last_ts"] = min(g["first_ts"], e["ts"]), max(g["last_ts"], e["ts"])
        g["cti"] = g["cti"] or bool(e.get("cti_match"))
        g["incident_id"] = e.get("incident_id") or g["incident_id"]
    out = []
    for g in groups.values():
        inc = incidents.get(g["incident_id"]) if g["incident_id"] else None
        g["status"] = inc["status"] if inc else "new"
        g["assignee"] = inc.get("assignee") if inc else None
        g["urgency"] = urgency(g["severity"], g["occurrences"], g["cti"], bool(inc and inc.get("coordinated")))
        out.append(g)
    out.sort(key=lambda g: (-g["urgency"], -g["last_ts"]))
    return out[:limit]


def top_threats(events: list[dict], since: float, limit: int = 10) -> list[dict]:
    c = Counter(e["technique"] for e in events if e.get("technique") not in (None, "", "—") and e["ts"] >= since)
    return [{"technique": t, "name": TECHNIQUES.get(t, t), "alerts": n} for t, n in c.most_common(limit)]


def data_sources(sources: Counter) -> list[dict]:
    total = sum(sources.values()) or 1
    return [{"source": s, "events": n, "share": round(n / total, 4)} for s, n in sources.most_common(12)]


def notifications(user: str, tasks: list[dict], incidents: list[dict], now: float) -> list[dict]:
    out = []
    for t in tasks:
        if t.get("assignee") == user and t["status"] not in ("completed", "cancelled"):
            overdue = bool(t.get("due") and t["due"] < now)
            out.append({"kind": "task", "id": t["id"], "ts": t.get("updated_at") or t["created_at"],
                        "title": t["name"], "detail": f"{TASK_TH[t['status']]}{' · เลยกำหนด' if overdue else ''}",
                        "urgent": overdue})
    for i in incidents:
        if i.get("status") not in ("open", "investigating"):
            continue
        if i.get("assignee") == user:
            out.append({"kind": "incident", "id": i["id"], "ts": i["last_ts"], "title": i.get("title"),
                        "detail": f"มอบหมายให้คุณ · {i.get('severity')}", "urgent": i.get("severity") == "critical"})
        elif i.get("severity") == "critical" and not i.get("assignee") and now - i["last_ts"] <= 86400:
            out.append({"kind": "incident", "id": i["id"], "ts": i["last_ts"], "title": i.get("title"),
                        "detail": "critical · ยังไม่มีผู้รับผิดชอบ", "urgent": True})
    out.sort(key=lambda n: (not n["urgent"], -(n["ts"] or 0)))
    return out[:30]


def validate_task(t: dict) -> list[str]:
    errs = []
    if not (t.get("name") or "").strip():
        errs.append("ต้องมีชื่องาน")
    if t.get("status", "pending") not in TASK_STATUSES:
        errs.append("สถานะไม่ถูกต้อง")
    return errs


def by_status(tasks: list[dict]) -> dict:
    c = defaultdict(int)
    for t in tasks:
        c[t["status"]] += 1
    return dict(c)


def now() -> float:
    return time.time()
