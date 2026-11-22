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
import re
import time
from collections import Counter, deque
from typing import Any

from app import intel, soc_store
from app.agent_detect import AgentMonitor, _agent_state
from app.config import settings
from app.offensive_ai import OffensiveAIMonitor
from app.phase4 import RuleEngine
from app.modules import threatintel

DOMAINS = ["endpoint", "identity", "email", "network", "cloud", "data", "agent"]
SEV = ["info", "low", "medium", "high", "critical"]
INCIDENT_STATUSES = ("open", "investigating", "resolved", "false_positive", "closed")
ACTIVE = ("open", "investigating")
PLACEHOLDER_USERS = {"", "unknown", "-", "n/a", "none", "system", "SYSTEM", None}  # new alerts still correlate into these
CORR_WINDOW = 1800

HOSTS = [("FIN-WS-014", "Windows 11", "finance.ops"), ("FIN-WS-022", "Windows 11", "ap.clerk"),
         ("HR-LT-007", "Windows 11", "hr.admin"), ("SALES-LT-031", "macOS 15", "sales.lead"),
         ("DEV-WS-102", "Ubuntu 24.04", "dev.backend"), ("DEV-WS-118", "Windows 11", "dev.frontend"),
         ("EXEC-LT-001", "Windows 11", "exec.assistant"), ("IT-WS-003", "Windows 11", "it.helpdesk"),
         ("SRV-DC-01", "Windows Server 2022", "svc.backup"), ("SRV-FILE-02", "Windows Server 2022", "svc.files"),
         ("SRV-WEB-01", "Ubuntu 22.04", "svc.web"), ("SRV-SQL-01", "Windows Server 2019", "svc.sql"),
         ("SRV-AI-01", "Ubuntu 24.04", "svc.ai.support"), ("SRV-AI-02", "Ubuntu 24.04", "svc.ai.devops")]
BASE_HOSTS = HOSTS
COUNTRIES = ["TH", "SG", "US", "NL", "RU", "CN", "VN", "DE", "BR", "KR", "JP", "IN", "ID", "MY", "PH", "HK", "TW", "AU",
             "GB", "FR", "IT", "ES", "PL", "UA", "TR", "IR", "IL", "AE", "SA", "EG", "ZA", "NG", "KE", "CA", "MX", "AR",
             "CL", "CO", "PE", "SE", "NO", "FI", "DK", "CH", "AT", "BE", "CZ", "RO", "KZ", "PK"]


def scaled_hosts(scale: int) -> list[tuple[str, str, str]]:
    """The 14 demo hosts plus (scale - 1) copies per department, e.g. FIN-WS-114 / finance.ops2 (simulated)."""
    out = list(BASE_HOSTS)
    for k in range(2, scale + 1):
        for name, os_, user in BASE_HOSTS:
            m = re.search(r"(\d+)$", name)
            step = 10 if name.startswith("SRV") else 100
            out.append((name[:m.start()] + f"{int(m.group(1)) + step * (k - 1):0{len(m.group(1))}d}", os_, f"{user}{k}"))
    return out

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


SIM_SOURCE = {"endpoint": "EDR", "identity": "Identity / IdP", "email": "Email gateway", "network": "NDR / Firewall",
              "cloud": "Cloud audit", "data": "Database / DLP", "agent": "AI agent audit"}
KIND_SOURCE = {"process": "EDR process", "http": "Web / proxy", "net": "Network flow", "logon": "Identity logon",
               "db": "Database audit", "dlp": "DLP", "agent": "AI agent audit", "prompt": "AI agent audit",
               "tool_call": "AI agent audit", "llm_call": "AI agent audit", "auth": "AI agent audit"}


MAX_ASSETS = 50000 * settings.soc_scale
PRIORITY_SEV = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
CASE_FIELDS = ("priority", "tags", "custom_fields", "name", "description")


def sev_up(s: str) -> str:
    return SEV[min(SEV.index(s) + 1, len(SEV) - 1)]


class Engine:
    def __init__(self, seed: int | None = None, max_events: int | None = None, simulate: bool = True, tenant: str = "default",
                 scale: int = 1):
        self.scale = scale
        self.hosts = scaled_hosts(scale) if simulate else []
        max_events = max_events or 300 * scale
        self.tenant = tenant
        self.simulate = simulate
        self.persist = False  # switched on by the app after restore(); tests use in-memory engines
        self.on_incident = None  # optional callback(incident) — the app wires the notifier here
        self._dirty: set[int] = set()
        self.ingested: Counter = Counter()
        self.sources: Counter = Counter()
        self.assets: dict[tuple, dict] = {}  # (type, name) -> discovered asset
        self.disabled_rules: set[str] = set()
        self.ioc_lookup = None  # callable -> {indicator value: indicator}; set by the app (tenant IOCs + CTI feeds)
        self._ioc_last: dict[tuple, float] = {}  # rules switched off in the rules catalog (per tenant)
        self.suppressed: Counter = Counter()  # events received per data source, for the "events by data source" widget
        self._outbox: deque[dict] = deque(maxlen=500 * scale)
        self._agent_outbox: deque[dict] = deque(maxlen=500 * scale)
        self.rng = random.Random(seed)
        self.ids = itertools.count(1)
        self.inc_ids = itertools.count(1001)
        self.events: deque[dict] = deque(maxlen=max_events)
        self.incidents: dict[int, dict] = {}
        self.totals: Counter = Counter()
        self.by_tactic: Counter = Counter()
        self.campaigns: list[dict] = []
        self.next_campaign_at = 0.0
        self.endpoints = {h: {"host": h, "os": os_, "user": u, "status": "healthy",
                              "realtime_protection": True, "last_seen": 0.0, "alerts": 0}
                          for h, os_, u in self.hosts}
        self.agents = AgentMonitor(self.rng, demo_inventory=simulate, scale=scale)
        self.offai = OffensiveAIMonitor(self.rng)
        self.custom = RuleEngine()
        self.raw: deque[dict] = deque(maxlen=5000 * scale)  # recent raw records, for back-testing custom rules
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
            ip = self.rng.choice(ips)
            fam = (threatintel.feed_index("feodo").get(ip) or {}).get("malware")
            return {"remote_ip": ip, "cti_match": "abuse.ch Feodo Tracker C2", **({"malware": fam} if fam else {})}
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
        for _ in range(sum(self.rng.choices([0, 1, 2, 3], [2, 4, 3, 1])[0] for _ in range(self.scale))):
            spec = self.rng.choice(NOISE)
            host, _, user = self.rng.choice(self.hosts)
            out.append(self._event(spec, host, user, now))
        for _ in range(self.scale):
            if self.rng.random() >= 0.06:
                continue
            kev = threatintel.kev_cves()
            web = self.rng.choice([h for h in self.hosts if h[0].startswith("SRV-WEB")] or [("SRV-WEB-01", "", "svc.web")])
            extra = {"host": web[0], "user": web[2]}
            if kev:
                v = self.rng.choice(kev)
                extra["cve"] = v["cve"]
                extra["cti_match"] = "CISA KEV"
            out.append(self._event(EXPLOIT, extra.pop("host"), extra.pop("user"), now, **extra))
        out.extend(self._advance_campaign(now))
        recs, alerts = self.agents.step(now)
        self.last_agent_records = agent_flushed + recs
        alerts += self.offai.step(now, self.scale)
        for a in alerts:
            out.append(self._event(a["spec"], a["host"], a["user"], now, **a["extra"]))
        for rec in list(self.offai.last_records) + recs:
            rec.setdefault("ts", now)
            self.raw.append(rec)
            out.extend(self._custom_events(rec, now))
        self.sources.update(f"{SIM_SOURCE.get(e['domain'], e['domain'])} (จำลอง)" for e in out)
        out = self._enabled(out)
        for e in out:
            self._touch_assets([{"host": e["host"], "user": e["user"], "agent": e.get("agent"), "ts": e["ts"]}],
                               f"{SIM_SOURCE.get(e['domain'], e['domain'])} (จำลอง)", real=False)
        self._asset_alerts([e for e in out if SEV.index(e["severity"]) >= 2])
        for ev in out:
            self._ingest(ev)
        return flushed + out

    # ---------- real telemetry ----------
    def ingest_external(self, records: list[dict], source: str | None = None, entity: str | None = None,
                        detect: bool = True) -> dict:
        """Run normalized real records (see app.ingest) through the detectors and the XDR correlator.
        `entity` tags every alert from this batch; detect=False stores logs only (entity in monitor mode)."""
        events: list[dict] = []
        agent_recs = [r for r in records if r.get("agent")]
        telemetry = [r for r in records if not r.get("agent")]
        if agent_recs:
            for rec in agent_recs:
                rec.setdefault("id", next(self.agents.sim.ids))
            if detect:
                for a, rec in self._agent_alerts(agent_recs):
                    events.append(self._event(a["spec"], a["host"], a["user"], rec["ts"], simulated=False, **a["extra"]))
            self._agent_outbox.extend(agent_recs)
        for rec in telemetry:
            if rec["kind"] == "process" and rec.get("host") and rec["host"] not in self.endpoints:
                self.endpoints[rec["host"]] = {"host": rec["host"], "os": rec.get("os") or "unknown",
                                               "user": rec.get("user") or "", "status": "healthy",
                                               "realtime_protection": True, "last_seen": rec["ts"], "alerts": 0}
            if detect:
                for a in self.offai.ingest([rec], rec["ts"], real=True):
                    events.append(self._event(a["spec"], a["host"], a["user"], rec["ts"], simulated=False, **a["extra"]))
        if detect and self.ioc_lookup:
            events.extend(self._ioc_events(records))
        for rec in records:
            rec["simulated"] = False
            rec["_source"] = source or "API"
            if entity:
                rec["_entity"] = entity
            self.raw.append(rec)
            if detect:
                events.extend(self._custom_events(rec, rec["ts"], simulated=False))
        events = self._enabled(events)
        if entity:
            for ev in events:
                ev["entity"] = entity
        for ev in events:
            self._ingest(ev)
        self._outbox.extend(events)
        touched_assets = self._touch_assets(records, source or "API", real=True) | self._asset_alerts(events)
        if self.persist:
            soc_store.save_events(events, self.tenant)
            soc_store.save_agent_records(agent_recs, self.tenant)
            soc_store.save_raw(records, self.tenant)
            touched = {r.get("host") for r in telemetry} | {e["host"] for e in events}
            soc_store.save_endpoints([self.endpoints[h] for h in touched if h in self.endpoints], self.tenant)
            soc_store.save_agents([self.agents.agents[a] for a in {r["agent"] for r in agent_recs}
                                   if a in self.agents.agents], self.tenant)
            soc_store.save_assets([self.assets[k] for k in touched_assets if self.assets[k].get("real")], self.tenant)
            self.flush()
        by_src = Counter(f"{source or 'API'} · {KIND_SOURCE.get(r['kind'], r['kind'])}" for r in records)
        self.sources.update(by_src)
        if self.persist:
            soc_store.add_counts({f"src:{k}": n for k, n in by_src.items()}, self.tenant)
        self.ingested.update(r["kind"] for r in records)
        self.ingested["total"] += len(records)
        return {"accepted": len(records), "alerts": len(events),
                "by_kind": dict(Counter(r["kind"] for r in records)),
                "alerts_by_rule": dict(Counter(e.get("rule") for e in events if e.get("rule")))}

    def _ioc_events(self, records: list[dict]) -> list[dict]:
        """IOC-001 (tenant IOC) / IOC-002 (public feed): an observable in the log equals a known indicator.
        One alert per indicator and host per 10 minutes."""
        index = self.ioc_lookup() or {}
        if not index:
            return []
        out = []
        for rec in records:
            hit = intel.match(rec, index)
            if not hit:
                continue
            host = rec.get("host") or rec.get("dest_host") or rec.get("dst_host") or rec.get("client_host") or "unknown"
            key = (hit["value"], host)
            if rec["ts"] - self._ioc_last.get(key, -1e18) < 600:
                continue
            self._ioc_last[key] = rec["ts"]
            if len(self._ioc_last) > 20000:
                self._ioc_last.clear()
            rid = "IOC-001" if hit["source"] == "tenant" else "IOC-002"
            sev = hit.get("severity") or ("high" if hit["confidence"] >= 80 else "medium" if hit["confidence"] >= 50 else "low")
            domain = {"process": "endpoint", "logon": "identity", "db": "data", "dlp": "data"}.get(rec.get("kind"), "network")
            title = f"[{rid}] Indicator seen: {hit['value'][:80]}" + (f" ({hit['threat']})" if hit.get("threat") else "")
            out.append(self._event((domain, title, sev, "T1071.001", "Command and Control"), host, rec.get("user") or "unknown",
                                   rec["ts"], simulated=False, rule=rid, cti_match=hit["source_name"], indicator=hit["value"],
                                   **({"malware": hit["threat"]} if hit.get("threat") else {})))
        return out

    # ---------- asset discovery (accounts, hosts, AI agents seen in logs) ----------
    def _asset(self, typ: str, name, ts: float, source: str, real: bool) -> tuple | None:
        name = str(name or "").strip()
        if not name or name.lower() in PLACEHOLDER_USERS or name in ("-", "?") or len(name) > 255:
            return None
        key = (typ, name)
        a = self.assets.get(key)
        if a is None:
            if len(self.assets) >= MAX_ASSETS:
                return None
            a = self.assets[key] = {"type": typ, "name": name, "first_seen": ts, "last_seen": ts, "events": 0,
                                    "alerts": 0, "sources": [], "tags": [], "revoked": False, "manual": False,
                                    "real": real}
        a["last_seen"] = max(a["last_seen"], ts)
        a["first_seen"] = min(a["first_seen"], ts)
        a["real"] = a.get("real") or real
        if source and source not in a["sources"] and len(a["sources"]) < 20:
            a["sources"].append(source)
        return key

    def _touch_assets(self, records: list[dict], source: str, real: bool) -> set:
        touched = set()
        for r in records:
            ts = r.get("ts") or time.time()
            keys = [self._asset("host", r.get(f), ts, source, real) for f in ("host", "dest_host", "src_host", "client_host")]
            keys.append(self._asset("account", r.get("user"), ts, source, real))
            if r.get("agent"):
                keys.append(self._asset("ai_agent", r.get("agent"), ts, source, real))
            for k in {k for k in keys if k}:
                self.assets[k]["events"] += 1
                touched.add(k)
        return touched

    def _asset_alerts(self, events: list[dict]) -> set:
        touched = set()
        for e in events:
            for typ, name in (("host", e.get("host")), ("account", e.get("user")), ("ai_agent", e.get("agent"))):
                k = (typ, str(name or "").strip())
                if k in self.assets:
                    self.assets[k]["alerts"] += 1
                    touched.add(k)
        return touched

    def _enabled(self, events: list[dict]) -> list[dict]:
        if not self.disabled_rules:
            return events
        keep = []
        for e in events:
            if e.get("rule") in self.disabled_rules:
                self.suppressed[e["rule"]] += 1
            else:
                keep.append(e)
        return keep

    def create_case(self, analyst: str, name: str, description: str = "", priority: str = "medium",
                    assignee: str | None = None, tags: list[str] | None = None, hosts: list[str] | None = None,
                    custom_fields: dict | None = None, now: float | None = None) -> dict:
        """A case opened by an analyst (not from correlation). Always kept: it is real work."""
        now = time.time() if now is None else now
        inc = {"id": next(self.inc_ids), "first_ts": now, "last_ts": now, "status": "open", "users": [],
               "hosts": list(hosts or []), "domains": [], "tactics": [], "alerts": [],
               "severity": PRIORITY_SEV.get(priority, "medium"), "priority": priority, "title": name, "name": name,
               "description": description, "type": "manual", "real": True, "assignee": assignee or None,
               "tags": list(tags or []), "custom_fields": dict(custom_fields or {}), "notes": [],
               "history": [{"ts": now, "analyst": analyst, "change": "case created manually"}],
               "created_by": analyst, "coordinated": False, "tenant": self.tenant}
        self.incidents[inc["id"]] = inc
        self._dirty.add(inc["id"])
        if self.persist:
            self.flush()
        return inc

    def _custom_events(self, rec: dict, now: float, simulated: bool | None = None) -> list[dict]:
        out = []
        for r in self.custom.evaluate(rec, now):
            kind = "agent" if rec.get("agent") else rec.get("kind")
            domain = {"process": "endpoint", "logon": "identity", "db": "data", "dlp": "data", "agent": "agent"}.get(kind, "network")
            host = rec.get("dst_host") or rec.get("dest_host") or rec.get("host") or "unknown"
            user = rec.get("user") or rec.get("on_behalf_of") or (f"src:{rec['src_ip']}" if rec.get("src_ip") else "unknown")
            extra = {"rule": r["id"], "detector": "custom",
                     "record": str(rec.get("cmdline") or rec.get("uri") or rec.get("summary") or rec.get("dest") or "")[:160]}
            if simulated is False or rec.get("simulated") is False:
                extra["simulated"] = False
            out.append(self._event((domain, f"[{r['id']}] {r.get('title', 'Custom rule')}", r.get("severity", "medium"),
                                    r.get("technique") or "—", r.get("tactic") or "Custom"), host, user, now, **extra))
        return out

    def flush(self) -> None:
        """Persist incidents that changed (real ones only)."""
        if self.persist and self._dirty:
            soc_store.save_incidents([self.incidents[i] for i in self._dirty if i in self.incidents], self.tenant)
        self._dirty.clear()

    def restore(self, data: dict) -> None:
        """Load persisted real state (see app.soc_store.load) and continue id sequences after it."""
        for ev in data["events"]:
            self.events.append(ev)
            self.totals[ev["domain"]] += 1
            self.totals["sev:" + ev["severity"]] += 1
            self.by_tactic[ev["tactic"]] += 1
        for ev in data["events"]:  # rule / framework hit counters shown on the dashboard
            rule = ev.get("rule") or ""
            if rule.startswith("AGT-"):
                self.agents.rule_hits[rule] += 1
            elif rule.startswith("OAI-"):
                self.offai.rule_hits[rule] += 1
                for fw in (ev.get("framework") or "").split():
                    self.offai.fw_hits[fw] += 1
        self.restored = len(data["events"])
        for inc in data["incidents"]:
            self.incidents[inc["id"]] = inc
        for ep in data["endpoints"]:
            self.endpoints[ep["host"]] = ep
        for a in data["agents"]:
            self.agents.agents[a["id"]] = _agent_state(a) | {k: a[k] for k in ("status", "contained", "alerts",
                                                                                "denied", "calls", "risk") if k in a}
        for r in data["agent_records"]:
            self.agents.records.append(r)
        self.ids = itertools.count(max(data["max_event_id"], max((e["id"] for e in self.events), default=0)) + 1)
        self.inc_ids = itertools.count(max(1000, data["max_incident_id"]) + 1)
        self.agents.sim.ids = itertools.count(max((r.get("id") or 0 for r in data["agent_records"]), default=0) + 1)

    def update_incident(self, inc_id: int, analyst: str, status: str | None = None, assignee: str | None = None,
                        note: str | None = None, now: float | None = None, verdict: str | None = None,
                        **fields) -> dict | None:
        inc = self.incidents.get(inc_id) or (soc_store.incident(inc_id, self.tenant) if self.persist else None)
        if inc is None:
            return None
        self.incidents.setdefault(inc_id, inc)
        now = time.time() if now is None else now
        inc.setdefault("notes", [])
        inc.setdefault("history", [])
        if status and status != inc["status"]:
            if status not in INCIDENT_STATUSES:
                raise ValueError(f"status must be one of {', '.join(INCIDENT_STATUSES)}")
            inc["history"].append({"ts": now, "analyst": analyst, "change": f"status {inc['status']} → {status}"})
            inc["status"] = status
        if assignee is not None and assignee != inc.get("assignee"):
            inc["history"].append({"ts": now, "analyst": analyst, "change": f"assignee → {assignee or '-'}"})
            inc["assignee"] = assignee or None
        for k, v in fields.items():
            if k in CASE_FIELDS and v is not None and v != inc.get(k):
                inc[k] = v
                if k == "name":
                    inc["title"] = v
                shown = ", ".join(v) if isinstance(v, list) else (str(v)[:60] if not isinstance(v, dict) else "updated")
                inc["history"].append({"ts": now, "analyst": analyst, "change": f"{k} → {shown or '-'}"})
        if verdict is not None and verdict != inc.get("verdict"):
            inc["history"].append({"ts": now, "analyst": analyst, "change": f"verdict → {verdict or '-'}"})
            inc["verdict"] = verdict or None
        if note:
            inc["notes"].append({"ts": now, "analyst": analyst, "text": note})
        if inc.get("real"):
            self._dirty.add(inc_id)
            self.flush()
        return inc

    def drop_outbox(self) -> None:
        self._outbox.clear()
        self._agent_outbox.clear()

    def _agent_alerts(self, recs: list[dict]):
        for rec in recs:
            for a in self.agents.ingest([rec], rec["ts"]):
                yield a, rec

    def _advance_campaign(self, now: float) -> list[dict]:
        """Multi-stage attack campaigns (simulated). Up to `scale` run at the same time on different hosts."""
        busy = {c["host"] for c in self.campaigns}
        if len(self.campaigns) < self.scale and now >= self.next_campaign_at and self.rng.random() <= 0.25:
            free = [h for h in self.hosts if not h[0].startswith("SRV") and h[0] not in busy]
            if free:
                host, _, user = self.rng.choice(free)
                self.campaigns.append({"host": host, "user": user, "stage": 0,
                                       "pivot": self.rng.choice([h[0] for h in self.hosts if h[0].startswith("SRV")])})
                if len(self.campaigns) >= self.scale:
                    self.next_campaign_at = now + 45
        out = []
        for c in list(self.campaigns):
            if self.rng.random() > 0.45:  # stages unfold over several ticks
                continue
            spec = CAMPAIGN[c["stage"]]
            host = c["pivot"] if spec[1].startswith(("Lateral", "Ransomware")) else c["host"]
            extra = self._c2() if "C2" in spec[1] else {}
            out.append(self._event(spec, host, c["user"], now, **extra))
            c["stage"] += 1
            if c["stage"] >= len(CAMPAIGN) or (c["stage"] > 4 and self.rng.random() < 0.15):
                self.campaigns.remove(c)  # contained or completed
                self.next_campaign_at = now + 45 / self.scale
        return out

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
            if self.on_incident:
                inc = self.incidents.get(ev["incident_id"])
                if inc and self.on_incident(inc) and inc.get("real"):
                    self._dirty.add(inc["id"])  # persist notified_sev so a restart does not re-send

    def _correlate(self, ev: dict) -> int:
        for inc in self.incidents.values():
            if inc["status"] not in ACTIVE or ev["ts"] - inc["last_ts"] > CORR_WINDOW or inc.get("type") == "manual":
                continue
            if inc.get("real", False) != (ev.get("simulated") is False):
                continue
            # placeholder accounts (no user in the log) must not glue unrelated hosts together
            user_match = ev["user"] not in PLACEHOLDER_USERS and ev["user"] in inc["users"]
            if user_match or (ev["host"] and ev["host"] in inc["hosts"]):
                break
        else:
            inc = {"id": next(self.inc_ids), "first_ts": ev["ts"], "status": "open", "users": [],
                   "hosts": [], "domains": [], "tactics": [], "alerts": [], "severity": "info",
                   "real": ev.get("simulated") is False, "assignee": None, "notes": [], "history": [],
                   "tenant": self.tenant}
            self.incidents[inc["id"]] = inc
        inc["last_ts"] = ev["ts"]
        for key, val in (("users", ev["user"]), ("hosts", ev["host"]), ("domains", ev["domain"]),
                         ("tactics", ev["tactic"])):
            if val not in inc[key]:
                inc[key].append(val)
        inc["alerts"].append({k: ev.get(k) for k in ("id", "ts", "domain", "title", "severity", "technique",
                                                     "host", "cti_match", "agent", "session", "rule", "malware", "cve",
                                                     "framework", "detector", "simulated", "user",
                                                     "record", "indicator", "source_url", "provider",
                                                     "region")})
        if inc.get("real"):
            self._dirty.add(inc["id"])
        base = max((a["severity"] for a in inc["alerts"]), key=SEV.index)
        inc["coordinated"] = len(inc["domains"]) >= 2 and SEV.index(base) >= SEV.index("high")
        inc["severity"] = sev_up(base) if inc["coordinated"] else base
        inc["title"] = inc.get("name") or ("Coordinated multi-domain attack" if inc["coordinated"]
                                           else inc["alerts"][0]["title"])
        cap = 200 * self.scale
        if len(self.incidents) > cap:  # memory bound: drop oldest inactive (real ones stay in SQLite)
            stale = [k for k in sorted(self.incidents) if self.incidents[k]["status"] not in ACTIVE]
            for k in stale[:len(self.incidents) - cap]:
                del self.incidents[k]
        return inc["id"]

    def expire(self, now: float) -> None:
        for inc in self.incidents.values():
            if inc["status"] == "open" and now - inc["last_ts"] > CORR_WINDOW and inc.get("type") != "manual":
                inc["status"] = "closed"  # auto-close idle, untriaged cases; analyst states are left alone
                inc.setdefault("history", []).append({"ts": now, "analyst": "system", "change": "status open → closed (idle)"})
                if inc.get("real"):
                    self._dirty.add(inc["id"])
        self.flush()

    # ---------- views ----------
    def stats(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        recent = [e for e in self.events if now - e["ts"] <= 60]
        open_inc = [i for i in self.incidents.values() if i["status"] in ACTIVE]
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
            "mode": {"simulation": self.simulate, "ingested": self.ingested["total"],
                     "restored": getattr(self, "restored", 0)},
        }

    def snapshot(self) -> dict[str, Any]:
        return {"events": list(self.events)[-80:], "incidents": self.incident_list(),
                "endpoints": list(self.endpoints.values()), "stats": self.stats(), "simulated": self.simulate,
                "agents": self.agents.inventory(), "agent_records": list(self.agents.records)[-60:],
                "rules": self.agents.rules(), "offai": self.offai.summary()}

    def incident_list(self) -> list[dict]:
        return sorted(self.incidents.values(), key=lambda i: (i["status"] not in ACTIVE, -i["last_ts"]))[:25]


class Hub:
    """One engine per tenant, ticking in the background and fanned out to that tenant's viewers only."""

    def __init__(self, interval: float = 1.0):
        self.engines: dict[str, Engine] = {}
        self.interval = interval
        self.subs: dict[str, set[asyncio.Queue]] = {}
        self.task: asyncio.Task | None = None
        self.cti_task: asyncio.Task | None = None
        self.setup = None  # callback(engine) run once when a tenant's engine is created (restore, rules, hooks)

    @property
    def engine(self) -> Engine:  # the default tenant (single-tenant deployments, tests)
        return self.engine_for(soc_store.DEFAULT)

    def engine_for(self, tenant: str) -> Engine:
        e = self.engines.get(tenant)
        if e is None:
            # only the default tenant runs the demo simulator; customer tenants see real data only
            e = self.engines[tenant] = Engine(scale=settings.soc_scale,
                                              simulate=settings.soc_simulation and tenant == soc_store.DEFAULT,
                                              tenant=tenant)
            if self.setup:
                self.setup(e)
        return e

    def ensure_running(self) -> None:
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._run())
        if self.cti_task is None or self.cti_task.done():
            self.cti_task = asyncio.create_task(self._cti_loop())

    def stop(self) -> None:
        for t in (self.task, self.cti_task):
            if t and not t.done():
                t.cancel()
        self.task = self.cti_task = None

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
            tick += 1
            for tenant, eng in list(self.engines.items()):
                events = eng.step(now)
                if tick % 10 == 0:
                    eng.expire(now)
                subs = self.subs.get(tenant)
                if not subs:
                    continue
                msg = {"events": events, "stats": eng.stats(now),
                       "incidents": eng.incident_list() if any("incident_id" in e for e in events)
                       or tick % 10 == 0 else None,
                       "endpoints": list(eng.endpoints.values()) if events else None,
                       "agent_records": eng.last_agent_records, "agents": eng.agents.inventory(),
                       "rules": eng.agents.rules(), "offai": eng.offai.summary()}
                for q in list(subs):
                    if q.qsize() < 50:
                        q.put_nowait(msg)
            await asyncio.sleep(self.interval)

    def has_subscribers(self, tenant: str) -> bool:
        return bool(self.subs.get(tenant))

    def subscribe(self, tenant: str = soc_store.DEFAULT) -> asyncio.Queue:
        self.ensure_running()
        self.engine_for(tenant)
        q: asyncio.Queue = asyncio.Queue()
        self.subs.setdefault(tenant, set()).add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        for subs in self.subs.values():
            subs.discard(q)


hub = Hub()
