"""EDR / XDR telemetry engine — SIMULATED events + real cross-domain correlation logic.

Domains: endpoint (EDR), identity, email, network (NDR), cloud, agent (AI-agent audit logs via
app.agent_detect). Telemetry is synthetic (demo) until a real EDR/XDR connector is plugged in; every event carries
"simulated": True. When live CTI is cached, simulated C2 / exploit events reference real
Feodo C2 IPs and CISA KEV CVEs and are flagged as CTI matches.

Correlation (the XDR part): alerts sharing an entity (user or host) inside CORR_WINDOW seconds are
merged into one incident. An incident spanning >= 2 domains with at least one high/critical alert is a
"coordinated attack" and is escalated one severity level.
"""
import asyncio
import itertools
import random
import time
from collections import Counter, deque
from typing import Any

from app.agent_detect import AgentMonitor
from app.config import settings
from app.offensive_ai import OffensiveAIMonitor
from app.modules import threatintel

DOMAINS = ["endpoint", "identity", "email", "network", "cloud", "agent"]
SEV = ["info", "low", "medium", "high", "critical"]
CORR_WINDOW = 1800

HOSTS = [("FIN-WS-014", "Windows 11", "finance.ops"), ("FIN-WS-022", "Windows 11", "ap.clerk"),
         ("HR-LT-007", "Windows 11", "hr.admin"), ("SALES-LT-031", "macOS 15", "sales.lead"),
         ("DEV-WS-102", "Ubuntu 24.04", "dev.backend"), ("DEV-WS-118", "Windows 11", "dev.frontend"),
         ("EXEC-LT-001", "Windows 11", "exec.assistant"), ("IT-WS-003", "Windows 11", "it.helpdesk"),
         ("SRV-DC-01", "Windows Server 2022", "svc.backup"), ("SRV-FILE-02", "Windows Server 2022", "svc.files"),
         ("SRV-WEB-01", "Ubuntu 22.04", "svc.web"), ("SRV-SQL-01", "Windows Server 2019", "svc.sql"),
         ("SRV-AI-01", "Ubuntu 24.04", "svc.ai.support"), ("SRV-AI-02", "Ubuntu 24.04", "svc.ai.devops")]
COUNTRIES = ["TH", "SG", "US", "NL", "RU", "CN", "VN", "DE", "BR", "KR"]

# (domain, title, severity, MITRE technique, tactic)
NOISE = [
    ("endpoint", "Unsigned binary executed from Downloads", "low", "T1204.002", "Execution"),
    ("endpoint", "PowerShell with encoded command", "medium", "T1059.001", "Execution"),
    ("endpoint", "New Run key persistence", "medium", "T1547.001", "Persistence"),
    ("endpoint", "Potentially unwanted app blocked", "low", "T1204", "Execution"),
    ("identity", "Sign-in from new country", "low", "T1078", "Initial Access"),
    ("identity", "Multiple failed sign-ins", "low", "T1110", "Credential Access"),
    ("email", "Phishing email quarantined", "low", "T1566.002", "Initial Access"),
    ("email", "Spam campaign blocked", "info", "T1566", "Initial Access"),
    ("network", "Inbound port scan blocked", "info", "T1046", "Discovery"),
    ("network", "Firewall: blocked outbound to rare domain", "low", "T1071.001", "Command and Control"),
    ("cloud", "Unusual file download volume", "low", "T1530", "Collection"),
    ("cloud", "New OAuth app consent", "medium", "T1528", "Credential Access"),
]

# Multi-stage kill chain executed against one user/host over successive ticks.
CAMPAIGN = [
    ("email", "Spear-phishing attachment delivered", "medium", "T1566.001", "Initial Access"),
    ("identity", "Suspicious sign-in (impossible travel)", "high", "T1078", "Initial Access"),
    ("identity", "MFA fatigue: push spam then approval", "high", "T1621", "Credential Access"),
    ("endpoint", "Office spawned PowerShell (encoded)", "high", "T1059.001", "Execution"),
    ("network", "C2 beacon to known botnet server", "critical", "T1071.001", "Command and Control"),
    ("endpoint", "Defender tampering attempt", "high", "T1562.001", "Defense Evasion"),
    ("endpoint", "LSASS memory access (credential dump)", "critical", "T1003.001", "Credential Access"),
    ("network", "Lateral movement via SMB admin share", "high", "T1021.002", "Lateral Movement"),
    ("cloud", "Mass download from SharePoint", "high", "T1530", "Collection"),
    ("network", "Large upload to file-sharing service", "critical", "T1567.002", "Exfiltration"),
    ("endpoint", "Ransomware behavior: mass file encryption", "critical", "T1486", "Impact"),
]
EXPLOIT = ("network", "Exploit attempt on public-facing app", "high", "T1190", "Initial Access")


def sev_up(s: str) -> str:
    return SEV[min(SEV.index(s) + 1, len(SEV) - 1)]


class Engine:
    def __init__(self, seed: int | None = None, max_events: int = 300, simulate: bool = True):
        self.simulate = simulate
        self.ingested: Counter = Counter()
        self._outbox: deque[dict] = deque(maxlen=500)
        self._agent_outbox: deque[dict] = deque(maxlen=500)
        self.rng = random.Random(seed)
        self.ids = itertools.count(1)
        self.inc_ids = itertools.count(1001)
        self.events: deque[dict] = deque(maxlen=max_events)
        self.incidents: dict[int, dict] = {}
        self.totals: Counter = Counter()
        self.by_tactic: Counter = Counter()
        self.campaign: dict | None = None
        self.next_campaign_at = 0.0
        self.endpoints = {h: {"host": h, "os": os_, "user": u, "status": "healthy",
                              "realtime_protection": True, "last_seen": 0.0, "alerts": 0}
                          for h, os_, u in (HOSTS if simulate else [])}
        self.agents = AgentMonitor(self.rng, demo_inventory=simulate)
        self.offai = OffensiveAIMonitor(self.rng)
        self.last_agent_records: list[dict] = []

    # ---------- generation ----------
    def _event(self, spec, host: str, user: str, now: float, **extra) -> dict:
        domain, title, sev, tech, tactic = spec
        ev = {"id": next(self.ids), "ts": now, "domain": domain, "title": title, "severity": sev,
              "technique": tech, "tactic": tactic, "host": host, "user": user,
              # synthetic geo only for simulated events; never invented for real telemetry
              "src_country": self.rng.choice(COUNTRIES) if extra.get("simulated", True) else None,
              "simulated": True, "cti_match": None}
        ev.update(extra)
        return ev

    def _c2(self) -> dict:
        ips = threatintel.c2_ips()
        if ips:
            return {"remote_ip": self.rng.choice(ips), "cti_match": "abuse.ch Feodo Tracker C2"}
        return {"remote_ip": f"203.0.113.{self.rng.randint(2, 250)}"}  # RFC 5737 doc range

    def step(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        flushed = list(self._outbox)  # events from ingested real logs, already counted
        self._outbox.clear()
        agent_flushed = list(self._agent_outbox)
        self._agent_outbox.clear()
        if not self.simulate:
            self.last_agent_records = agent_flushed
            return flushed
        out: list[dict] = []
        for _ in range(self.rng.choices([0, 1, 2, 3], [2, 4, 3, 1])[0]):
            spec = self.rng.choice(NOISE)
            host, _, user = self.rng.choice(HOSTS)
            out.append(self._event(spec, host, user, now))
        if self.rng.random() < 0.06:
            kev = threatintel.kev_cves()
            extra = {"host": "SRV-WEB-01", "user": "svc.web"}
            if kev:
                v = self.rng.choice(kev)
                extra["cve"] = v["cve"]
                extra["cti_match"] = "CISA KEV"
            out.append(self._event(EXPLOIT, extra.pop("host"), extra.pop("user"), now, **extra))
        out.extend(self._advance_campaign(now))
        recs, alerts = self.agents.step(now)
        self.last_agent_records = agent_flushed + recs
        alerts += self.offai.step(now)
        for a in alerts:
            out.append(self._event(a["spec"], a["host"], a["user"], now, **a["extra"]))
        for ev in out:
            self._ingest(ev)
        return flushed + out

    # ---------- real telemetry ----------
    def ingest_external(self, records: list[dict]) -> dict:
        """Run normalized real records (see app.ingest) through the detectors and the XDR correlator."""
        events: list[dict] = []
        agent_recs = [r for r in records if r.get("agent")]
        telemetry = [r for r in records if not r.get("agent")]
        if agent_recs:
            for rec in agent_recs:
                rec.setdefault("id", next(self.agents.sim.ids))
            for a, rec in self._agent_alerts(agent_recs):
                events.append(self._event(a["spec"], a["host"], a["user"], rec["ts"], simulated=False, **a["extra"]))
            self._agent_outbox.extend(agent_recs)
        for rec in telemetry:
            if rec["kind"] == "process" and rec.get("host") and rec["host"] not in self.endpoints:
                self.endpoints[rec["host"]] = {"host": rec["host"], "os": rec.get("os") or "unknown",
                                               "user": rec.get("user") or "", "status": "healthy",
                                               "realtime_protection": True, "last_seen": rec["ts"], "alerts": 0}
            for a in self.offai.ingest([rec], rec["ts"]):
                events.append(self._event(a["spec"], a["host"], a["user"], rec["ts"], simulated=False, **a["extra"]))
        for ev in events:
            self._ingest(ev)
        self._outbox.extend(events)
        self.ingested.update(r["kind"] for r in records)
        self.ingested["total"] += len(records)
        return {"accepted": len(records), "alerts": len(events),
                "by_kind": dict(Counter(r["kind"] for r in records)),
                "alerts_by_rule": dict(Counter(e.get("rule") for e in events if e.get("rule")))}

    def drop_outbox(self) -> None:
        self._outbox.clear()
        self._agent_outbox.clear()

    def _agent_alerts(self, recs: list[dict]):
        for rec in recs:
            for a in self.agents.ingest([rec], rec["ts"]):
                yield a, rec

    def _advance_campaign(self, now: float) -> list[dict]:
        if self.campaign is None:
            if now < self.next_campaign_at or self.rng.random() > 0.25:
                return []
            host, _, user = self.rng.choice([h for h in HOSTS if not h[0].startswith("SRV")])
            self.campaign = {"host": host, "user": user, "stage": 0,
                             "pivot": self.rng.choice([h[0] for h in HOSTS if h[0].startswith("SRV")])}
        c = self.campaign
        if self.rng.random() > 0.45:  # stages unfold over several ticks
            return []
        spec = CAMPAIGN[c["stage"]]
        host = c["pivot"] if spec[1].startswith(("Lateral", "Ransomware")) else c["host"]
        extra = self._c2() if "C2" in spec[1] else {}
        ev = self._event(spec, host, c["user"], now, **extra)
        c["stage"] += 1
        if c["stage"] >= len(CAMPAIGN) or (c["stage"] > 4 and self.rng.random() < 0.15):
            self.campaign = None  # contained or completed
            self.next_campaign_at = now + 45
        return [ev]

    # ---------- correlation ----------
    def _ingest(self, ev: dict) -> None:
        self.events.append(ev)
        self.totals[ev["domain"]] += 1
        self.totals["sev:" + ev["severity"]] += 1
        self.by_tactic[ev["tactic"]] += 1
        ep = self.endpoints.get(ev["host"])
        if ep:
            ep["last_seen"] = ev["ts"]
            if ev["domain"] == "endpoint" and SEV.index(ev["severity"]) >= 2:
                ep["alerts"] += 1
            if ev["technique"] == "T1562.001":
                ep["realtime_protection"] = False
            if SEV.index(ev["severity"]) >= 4:
                ep["status"] = "compromised"
            elif SEV.index(ev["severity"]) >= 3 and ep["status"] == "healthy":
                ep["status"] = "at_risk"
        if SEV.index(ev["severity"]) >= 2:
            ev["incident_id"] = self._correlate(ev)

    def _correlate(self, ev: dict) -> int:
        for inc in self.incidents.values():
            if inc["status"] != "open" or ev["ts"] - inc["last_ts"] > CORR_WINDOW:
                continue
            if ev["user"] in inc["users"] or ev["host"] in inc["hosts"]:
                break
        else:
            inc = {"id": next(self.inc_ids), "first_ts": ev["ts"], "status": "open", "users": [],
                   "hosts": [], "domains": [], "tactics": [], "alerts": [], "severity": "info"}
            self.incidents[inc["id"]] = inc
        inc["last_ts"] = ev["ts"]
        for key, val in (("users", ev["user"]), ("hosts", ev["host"]), ("domains", ev["domain"]),
                         ("tactics", ev["tactic"])):
            if val not in inc[key]:
                inc[key].append(val)
        inc["alerts"].append({k: ev.get(k) for k in ("id", "ts", "domain", "title", "severity", "technique",
                                                     "host", "cti_match", "agent", "session", "rule",
                                                     "framework", "detector")})
        base = max((a["severity"] for a in inc["alerts"]), key=SEV.index)
        inc["coordinated"] = len(inc["domains"]) >= 2 and SEV.index(base) >= SEV.index("high")
        inc["severity"] = sev_up(base) if inc["coordinated"] else base
        inc["title"] = ("Coordinated multi-domain attack" if inc["coordinated"]
                        else inc["alerts"][0]["title"])
        if len(self.incidents) > 60:  # drop oldest closed/stale
            for k in sorted(self.incidents)[:len(self.incidents) - 60]:
                del self.incidents[k]
        return inc["id"]

    def expire(self, now: float) -> None:
        for inc in self.incidents.values():
            if inc["status"] == "open" and now - inc["last_ts"] > CORR_WINDOW:
                inc["status"] = "closed"

    # ---------- views ----------
    def stats(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        recent = [e for e in self.events if now - e["ts"] <= 60]
        open_inc = [i for i in self.incidents.values() if i["status"] == "open"]
        return {
            "ts": now,
            "events_per_min": len(recent),
            "per_domain_min": {d: sum(1 for e in recent if e["domain"] == d) for d in DOMAINS},
            "totals": {d: self.totals[d] for d in DOMAINS},
            "severity": {s: self.totals["sev:" + s] for s in SEV},
            "tactics": dict(self.by_tactic.most_common()),
            "open_incidents": len(open_inc),
            "coordinated": sum(1 for i in open_inc if i.get("coordinated")),
            "cti_hits": sum(1 for e in self.events if e.get("cti_match")),
            "endpoints": {s: sum(1 for ep in self.endpoints.values() if ep["status"] == s)
                          for s in ("healthy", "at_risk", "compromised")},
            "mode": {"simulation": self.simulate, "ingested": self.ingested["total"]},
        }

    def snapshot(self) -> dict[str, Any]:
        return {"events": list(self.events)[-80:], "incidents": self.incident_list(),
                "endpoints": list(self.endpoints.values()), "stats": self.stats(), "simulated": self.simulate,
                "agents": self.agents.inventory(), "agent_records": list(self.agents.records)[-60:],
                "rules": self.agents.rules(), "offai": self.offai.summary()}

    def incident_list(self) -> list[dict]:
        return sorted(self.incidents.values(), key=lambda i: (i["status"] != "open", -i["last_ts"]))[:25]


class Hub:
    """One shared engine ticking in the background, fanned out to every dashboard viewer."""

    def __init__(self, interval: float = 1.0):
        self.engine = Engine(simulate=settings.soc_simulation)
        self.interval = interval
        self.subs: set[asyncio.Queue] = set()
        self.task: asyncio.Task | None = None
        self.cti_task: asyncio.Task | None = None

    def ensure_running(self) -> None:
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._run())
        if self.cti_task is None or self.cti_task.done():
            self.cti_task = asyncio.create_task(self._cti_loop())

    async def _cti_loop(self) -> None:
        while True:
            try:
                await threatintel.get_all()
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(threatintel.CACHE_TTL)

    async def _run(self) -> None:
        tick = 0
        while True:
            now = time.time()
            events = self.engine.step(now)
            tick += 1
            if tick % 10 == 0:
                self.engine.expire(now)
            msg = {"events": events, "stats": self.engine.stats(now),
                   "incidents": self.engine.incident_list() if any("incident_id" in e for e in events)
                   or tick % 10 == 0 else None,
                   "endpoints": list(self.engine.endpoints.values()) if events else None,
                   "agent_records": self.engine.last_agent_records, "agents": self.engine.agents.inventory(),
                   "rules": self.engine.agents.rules(), "offai": self.engine.offai.summary()}
            for q in list(self.subs):
                if q.qsize() < 50:
                    q.put_nowait(msg)
            await asyncio.sleep(self.interval)

    def subscribe(self) -> asyncio.Queue:
        self.ensure_running()
        q: asyncio.Queue = asyncio.Queue()
        self.subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subs.discard(q)


hub = Hub()
