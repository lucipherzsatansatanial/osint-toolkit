"""Detection of offensive AI-agent frameworks (ARTEX/AntiFox, Cairn, PentAGI, HexStrike, CyberStrikeAI,
Strix, Hermes Agent, Agent Zero) from EDR / NDR / web / proxy telemetry.

Two layers:
1. Behaviour rules (OAI-001..005, 007): durable, tool-agnostic. Operators can change user agents and
   banners; they rarely change *how* an agent works (approvals off, machine-speed tool fan-out,
   rotating proxies, multi-stage chains, model-API egress).
2. Indicator match (OAI-006): the community indicator set from
   github.com/ThreatDefence/agentic-attack-detections (MIT), loaded live by app.modules.threatintel.
   A handful of high-confidence seeds from that set are bundled so the demo works offline.

Record shapes (kind):
  process: host, user, pid, ppid, image, cmdline, parent_image?, parent_cmdline?
  http   : dst_host, src_ip, method, uri, status, ua          (web server / WAF / reverse proxy log)
  net    : host, dest, dest_ip, port                           (EDR network / NDR / DNS / proxy egress)
"""
import itertools
import re
from collections import Counter, defaultdict, deque

from app.config import settings
from app.modules import threatintel

SOURCE = "https://github.com/ThreatDefence/agentic-attack-detections"
FRAMEWORKS = {
    "artex": ("ARTEX / AntiFox", "Autonomous pentest console (ARTEX) and its AntiFox fork; renamed builds exist"),
    "cairn": ("Cairn", "Fact-graph exploration; Claude Code / Codex / Pi workers in a Kali container"),
    "pentagi": ("PentAGI", "Autonomous pentest platform (vxcontrol); customized builds seen in Asia"),
    "hexstrike": ("HexStrike AI", "MCP tool server exposing ~150 security tools, API on 8888"),
    "cyberstrikeai": ("CyberStrikeAI", "Go console with ~90 tools, implant builder, C2 and webshell manager"),
    "strix": ("Strix", "Python AI pentest agents in a Kali sandbox behind a Caido proxy"),
    "hermes": ("Hermes Agent", "General agent abused with approvals off (--yolo) and a jailbreak skill"),
    "agent-zero": ("Agent Zero", "General agent in a Kali container with a built-in hacker profile"),
}
# Verbatim high-confidence seeds from the ThreatDefence indicators.csv (offline fallback only).
SEED = [
    ("user_agent", "HexStrike-HTTP-Framework/1.0", "high", "hexstrike"),
    ("user_agent", "HexStrike-BrowserAgent/1.0", "high", "hexstrike"),
    ("user_agent", "CyberStrikeAI-WebShell/1.0", "high", "cyberstrikeai"),
    ("string", ":OSPROBE_", "high", "cyberstrikeai"),
    ("user_agent", "artex-pentest/1.0", "high", "artex"),
    ("user_agent", "ARTEX-worker/1.0", "high", "artex"),
    ("string", "hexstrikeXSSTest123", "high", "hexstrike"),
    ("file_name", "hexstrike_server.py", "high", "hexstrike"),
    ("docker_image", "ghcr.io/usestrix/strix-sandbox", "high", "strix"),
    ("string", "HERMES_YOLO_MODE", "high", "hermes"),
    ("docker_image", "vxcontrol/kali-linux", "high", "pentagi"),
    ("docker_image", "ghcr.io/oritera/cairn-worker-container", "high", "cairn"),
    ("docker_image", "agent0ai/agent-zero", "medium", "agent-zero"),
]

# Model-API hostnames. region "CN" = provider based in mainland China. Verify before blocking.
LLM_APIS = {
    "api.openai.com": ("OpenAI", "US"), "api.anthropic.com": ("Anthropic", "US"),
    "generativelanguage.googleapis.com": ("Google Gemini", "US"), "api.x.ai": ("xAI", "US"),
    "api.mistral.ai": ("Mistral", "EU"), "api.groq.com": ("Groq", "US"), "openrouter.ai": ("OpenRouter", "US"),
    "api.together.xyz": ("Together", "US"),
    "api.deepseek.com": ("DeepSeek", "CN"), "dashscope.aliyuncs.com": ("Alibaba Qwen (DashScope)", "CN"),
    "dashscope-intl.aliyuncs.com": ("Alibaba Qwen (DashScope intl)", "CN"),
    "open.bigmodel.cn": ("Zhipu GLM", "CN"), "api.moonshot.cn": ("Moonshot Kimi", "CN"),
    "api.minimax.chat": ("MiniMax", "CN"), "api.minimaxi.com": ("MiniMax", "CN"),
    "ark.cn-beijing.volces.com": ("ByteDance Doubao (Volcengine Ark)", "CN"),
    "api.siliconflow.cn": ("SiliconFlow", "CN"), "qianfan.baidubce.com": ("Baidu Qianfan", "CN"),
}
AGENT_CLIS = {"claude", "codex", "gemini", "qwen", "kimi", "opencode", "hermes", "pi", "aider", "cursor-agent"}
APPROVAL_BYPASS = re.compile(
    r"(--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--full-auto|--yolo\b|"
    r"--approval-mode[ =]yolo|--permission-mode[ =]bypassPermissions|--auto-approve|--yes-always|"
    r"HERMES_YOLO_MODE|approvals\.mode:\s*off)", re.I)
RECON_TOOLS = {"nmap", "masscan", "naabu", "subfinder", "amass", "httpx", "katana", "whatweb", "dnsx"}
SCAN_TOOLS = {"nuclei", "ffuf", "gobuster", "feroxbuster", "dirsearch", "sqlmap", "nikto", "wpscan", "dalfox"}
EXPLOIT_TOOLS = {"msfconsole", "hydra", "medusa", "searchsploit", "interactsh-client"}
POST_TOOLS = {"netexec", "nxc", "crackmapexec", "impacket-secretsdump", "impacket-psexec", "secretsdump.py",
              "psexec.py", "kerbrute", "responder", "mimikatz", "rubeus", "evil-winrm", "chisel", "ligolo"}
OFFENSIVE = RECON_TOOLS | SCAN_TOOLS | EXPLOIT_TOOLS | POST_TOOLS
OAST = ("oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me", "interact.sh",
        "burpcollaborator.net", "oastify.com", "dnslog.cn", "webhook.site", "requestrepo.com")
PROBE_URI = re.compile(r"(/\.env\b|/\.git/|/wp-config|/etc/passwd|\.\./|'\s*or\s*'|union\s+select|/actuator|/server-status)", re.I)

RULES = {
    "OAI-001": ("AI agent CLI with approvals disabled launched attack tooling", "high", "T1059", "Execution"),
    "OAI-002": ("Server called external AI model API", "medium", "T1071.001", "Command and Control"),
    "OAI-003": ("Rapid offensive-tool fan-out from one source", "high", "T1595", "Reconnaissance"),
    "OAI-004": ("Recon through rotating proxies (many IPs, one target)", "medium", "T1090.002", "Reconnaissance"),
    "OAI-005": ("Autonomous multi-stage chain (recon→scan→exploit→post)", "critical", "T1190", "Initial Access"),
    "OAI-006": ("Known offensive-AI framework indicator", "high", "T1588.002", "Resource Development"),
    "OAI-007": ("Out-of-band (OAST) callback", "medium", "T1071.004", "Command and Control"),
}
STAGES = ["recon", "scan", "exploit", "post"]
SERVER_PREFIXES = tuple(p.upper() for p in settings.server_prefixes) or ("SRV",)
FANOUT_TOOLS, FANOUT_WINDOW = 4, 120
PROXY_IPS, PROXY_WINDOW = 20, 300
CHAIN_STAGES, CHAIN_WINDOW = 3, 900


def tool_name(image: str) -> str:
    base = re.split(r"[\\/]", image or "")[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def llm_api(dest: str):
    dest = (dest or "").lower().rstrip(".")
    for host, meta in LLM_APIS.items():
        if dest == host or dest.endswith("." + host):
            return host, meta
    return None


class IndicatorIndex:
    """Matches telemetry fields against the agentic indicator set with false-positive guards."""

    def __init__(self, rows: list[dict] | None = None):
        rows = rows or [{"type": t, "value": v, "confidence": c, "framework": f, "source_url": SOURCE}
                        for t, v, c, f in SEED]
        self.rows = rows
        self.by_type: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            v = (r.get("value") or "").strip()
            if r.get("confidence") == "low" or len(v) < 6:
                continue  # low-confidence rows are legitimate services / generic values: hunt, don't alert
            if "applewebkit" in v.lower() and r["type"] in ("user_agent", "string"):
                continue  # generic browser strings would match every visitor
            self.by_type[r["type"]].append({**r, "_v": v.lower()})

    def match(self, rec: dict) -> list[dict]:
        hay = {
            "ua": (rec.get("ua") or "").lower(),
            "text": " ".join(str(rec.get(k) or "") for k in ("cmdline", "image", "uri", "container")).lower(),
            "addr": {(rec.get(k) or "").lower() for k in ("src_ip", "dest", "dest_ip") if rec.get(k)},
        }
        hits = []
        for r in self.by_type.get("user_agent", []):
            if r["_v"] in hay["ua"]:
                hits.append(r)
        for t in ("string", "uri_string", "file_name", "file_path", "docker_image"):
            for r in self.by_type.get(t, []):
                if r["_v"] in hay["text"] or (t in ("string", "uri_string") and r["_v"] in hay["ua"]):
                    hits.append(r)
        for t in ("ipv4", "domain"):
            for r in self.by_type.get(t, []):
                if r["_v"] in hay["addr"]:
                    hits.append(r)
        return hits


class Detector:
    def __init__(self, approved_ai_hosts: set[str] | None = None):
        self.approved = approved_ai_hosts or set()
        self.procs: dict[tuple, dict] = {}  # (host, pid) -> process
        self.fanout: dict[str, deque] = defaultdict(deque)  # source -> (ts, tool)
        self.inbound: dict[str, deque] = defaultdict(deque)  # target -> (ts, src_ip, status)
        self.stages: dict[str, dict] = defaultdict(dict)  # entity -> stage -> ts
        self.fired: dict[tuple, float] = {}
        self.index = IndicatorIndex()

    def _once(self, key: tuple, now: float, every: float = 600) -> bool:
        last = self.fired.get(key)
        if last is not None and now - last < every:
            return False
        self.fired[key] = now
        return True

    def _ancestor_bypass(self, host: str, pid, rec: dict | None = None) -> dict | None:
        # EDR rows (Defender, ECS) carry the parent's command line, so check it before walking the tree
        if rec and rec.get("parent_cmdline") and tool_name(rec.get("parent_image", "")) in AGENT_CLIS \
                and APPROVAL_BYPASS.search(rec["parent_cmdline"]):
            return {"pid": pid, "cmdline": rec["parent_cmdline"]}
        seen = 0
        while pid is not None and seen < 6:
            p = self.procs.get((host, pid))
            if p is None:
                return None
            if tool_name(p["image"]) in AGENT_CLIS and APPROVAL_BYPASS.search(p.get("cmdline", "")):
                return p
            pid, seen = p.get("ppid"), seen + 1
        return None

    def _stage(self, rec: dict) -> str | None:
        k = rec["kind"]
        if k == "process":
            t = tool_name(rec.get("image", ""))
            for stage, tools in (("recon", RECON_TOOLS), ("scan", SCAN_TOOLS), ("exploit", EXPLOIT_TOOLS),
                                 ("post", POST_TOOLS)):
                if t in tools:
                    return stage
            if ":OSPROBE_" in rec.get("cmdline", "") or "whoami" in rec.get("cmdline", ""):
                return "post"
        elif k == "http":
            uri = rec.get("uri", "")
            if ":OSPROBE_" in uri or re.search(r"\.(jsp|php|aspx)\?(cmd|c|pass)=", uri, re.I):
                return "post"
            if rec.get("method") == "POST" and re.search(r"upload|\.jsp|\.php", uri, re.I) and rec.get("status") == 200:
                return "exploit"
            if PROBE_URI.search(uri):
                return "scan"
            if rec.get("status") == 404:
                return "recon"
        elif k == "net":
            d = (rec.get("dest") or "").lower()
            if any(d == o or d.endswith("." + o) for o in OAST):
                return "exploit"
            if 28000 <= int(rec.get("port") or 0) <= 29999:
                return "post"
        return None

    def evaluate(self, rec: dict, now: float) -> list[tuple[str, dict]]:
        out: list[tuple[str, dict]] = []
        k = rec["kind"]
        entity = rec.get("dst_host") if k == "http" else rec.get("host")
        if k == "process":
            self.procs[(rec["host"], rec["pid"])] = rec
            t = tool_name(rec.get("image", ""))
            if t in OFFENSIVE:
                parent = self._ancestor_bypass(rec["host"], rec.get("ppid"), rec)
                if parent and self._once(("OAI-001", rec["host"], parent["pid"]), now):
                    out.append(("OAI-001", {"agent_cmdline": parent["cmdline"][:200]}))
                src = f'{rec["host"]}:{rec.get("ppid")}'
                q = self.fanout[src]
                q.append((now, t))
                while q and now - q[0][0] > FANOUT_WINDOW:
                    q.popleft()
                tools = {x for _, x in q}
                if len(tools) >= FANOUT_TOOLS and self._once(("OAI-003", src), now):
                    out.append(("OAI-003", {"tools": sorted(tools)}))
        elif k == "net":
            hit = llm_api(rec.get("dest"))
            host = rec.get("host", "")
            approved = (host, hit[0]) in self.approved or (host, "*") in self.approved if hit else False
            if hit and host.upper().startswith(SERVER_PREFIXES) and not approved \
                    and self._once(("OAI-002", host, hit[0]), now, 1800):
                provider, region = hit[1]
                out.append(("OAI-002", {"provider": provider, "region": region, "dest": hit[0],
                                        "severity": "high" if region == "CN" else None}))
            d = (rec.get("dest") or "").lower()
            if any(d == o or d.endswith("." + o) for o in OAST) and self._once(("OAI-007", host, d), now):
                out.append(("OAI-007", {"dest": d}))
        elif k == "http":
            q = self.inbound[entity]
            q.append((now, rec.get("src_ip"), rec.get("status")))
            while q and now - q[0][0] > PROXY_WINDOW:
                q.popleft()
            # count "probe-like" sources: few requests each, mostly errors. Normal visitors (mostly 2xx)
            # and single heavy scanners (many requests from one IP) are excluded.
            per_ip, err_ip = Counter(), Counter()
            for _, ip, status in q:
                per_ip[ip] += 1
                err_ip[ip] += 1 if status and status >= 400 else 0
            probers = [ip for ip, n in per_ip.items() if n <= 5 and err_ip[ip] / n >= 0.6]
            if len(probers) >= PROXY_IPS and self._once(("OAI-004", entity), now):
                out.append(("OAI-004", {"distinct_ips": len(probers),
                                        "requests": sum(per_ip[ip] for ip in probers)}))
        for ind in self.index.match(rec):
            fw = ind.get("framework", "")
            if self._once(("OAI-006", entity, ind["_v"]), now):
                out.append(("OAI-006", {"framework": fw, "indicator": ind["value"][:120], "ioc_type": ind["type"],
                                        "confidence": ind.get("confidence"), "source_url": ind.get("source_url"),
                                        "severity": "high" if ind.get("confidence") == "high" else "medium"}))
        stage = self._stage(rec)
        if stage and entity:
            st = self.stages[entity]
            st[stage] = now
            for s in list(st):
                if now - st[s] > CHAIN_WINDOW:
                    del st[s]
            if len(st) >= CHAIN_STAGES and ({"exploit", "post"} & set(st)) and self._once(("OAI-005", entity), now, 1800):
                out.append(("OAI-005", {"stages": [s for s in STAGES if s in st]}))
        return out


class OffensiveAISim:
    """Simulated telemetry: external agentic campaign via rotating proxies, an agent CLI in yolo mode
    fanning out attack tools on a workstation, and servers calling model APIs."""

    def __init__(self, rng):
        self.rng = rng
        self.pids = itertools.count(20000)
        self.camp: dict | None = None
        self.yolo: dict | None = None
        self.next_camp = 30.0
        self.next_yolo = 60.0

    def _ip(self):
        return f"{self.rng.choice(['198.51.100', '203.0.113', '192.0.2'])}.{self.rng.randint(2, 254)}"

    def _ua(self, fw: str) -> str:
        idx = threatintel.agentic_index()
        uas = [r["value"] for r in idx if r.get("framework", "").split()[0] == fw and r["type"] == "user_agent"
               and r.get("confidence") == "high"] if idx else []
        uas = uas or [v for t, v, c, f in SEED if f == fw and t == "user_agent"]
        return self.rng.choice(uas)

    def step(self, now: float) -> list[dict]:
        r: list[dict] = []
        for _ in range(self.rng.randint(0, 2)):  # benign web traffic
            r.append({"kind": "http", "dst_host": "SRV-WEB-01", "src_ip": f"10.1.{self.rng.randint(0, 9)}.{self.rng.randint(2, 200)}",
                      "method": "GET", "uri": self.rng.choice(["/", "/login", "/api/v1/status", "/assets/app.js"]),
                      "status": 200, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0"})
        if self.rng.random() < 0.05:  # approved AI servers / unapproved servers calling model APIs
            host, dest = self.rng.choice([("SRV-AI-01", "api.anthropic.com"), ("SRV-AI-02", "api.openai.com"),
                                          ("SRV-FILE-02", "api.deepseek.com"), ("SRV-SQL-01", "dashscope.aliyuncs.com"),
                                          ("SRV-WEB-01", "open.bigmodel.cn"), ("SRV-DC-01", "openrouter.ai")])
            r.append({"kind": "net", "host": host, "dest": dest, "dest_ip": self._ip(), "port": 443})
        if self.rng.random() < 0.02:  # helpdesk runs one nmap: should stay quiet
            r.append({"kind": "process", "host": "IT-WS-003", "user": "it.helpdesk", "pid": next(self.pids), "ppid": 1,
                      "image": "nmap.exe", "cmdline": "nmap -sn 10.0.3.0/24"})
        r += self._campaign(now) + self._yolo(now)
        for x in r:
            x.update(ts=now, simulated=True)
        return r

    def _campaign(self, now):
        if self.camp is None:
            if now < self.next_camp or self.rng.random() > 0.05:
                return []
            self.camp = {"fw": self.rng.choice(["hexstrike", "cyberstrikeai", "artex"]), "stage": 0}
        c, out = self.camp, []
        if self.rng.random() > 0.55:
            return []
        tgt = "SRV-WEB-01"
        if c["stage"] in (0, 1):  # recon through rotating proxies: many IPs, few requests each, mostly 404
            for _ in range(self.rng.randint(14, 22)):
                out.append({"kind": "http", "dst_host": tgt, "src_ip": self._ip(), "method": "GET",
                            "uri": self.rng.choice(["/admin", "/backup.zip", "/old/", "/api/v2/", "/test.php"]),
                            "status": 404, "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/129.0"})
        elif c["stage"] == 2:
            for uri in ("/.env", "/.git/config", "/api/v1/users?id=1' OR '1'='1"):
                out.append({"kind": "http", "dst_host": tgt, "src_ip": self._ip(), "method": "GET", "uri": uri,
                            "status": 403, "ua": self._ua(c["fw"])})
        elif c["stage"] == 3:
            out.append({"kind": "http", "dst_host": tgt, "src_ip": self._ip(), "method": "POST",
                        "uri": "/upload/avatar.php", "status": 200, "ua": self._ua(c["fw"])})
            out.append({"kind": "net", "host": tgt, "dest": f"{self.rng.randint(10**7, 10**8)}x.oast.fun",
                        "dest_ip": self._ip(), "port": 53})
        else:
            out.append({"kind": "http", "dst_host": tgt, "src_ip": self._ip(), "method": "GET",
                        "uri": "/upload/f1219a.jsp?cmd=echo%20:OSPROBE_%OS%:END", "status": 200,
                        "ua": "Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)" if c["fw"] == "cyberstrikeai"
                        else self._ua(c["fw"])})
            out.append({"kind": "process", "host": tgt, "user": "svc.web", "pid": next(self.pids), "ppid": 900,
                        "image": "/bin/sh", "cmdline": "sh -c whoami; id; uname -a"})
            self.camp, self.next_camp = None, now + 120
        if self.camp:
            c["stage"] += 1
        for x in out:
            x["framework_sim"] = c["fw"]
        return out

    def _yolo(self, now):
        if self.yolo is None:
            if now < self.next_yolo or self.rng.random() > 0.04:
                return []
            cli = self.rng.choice([
                ("claude", "claude --dangerously-skip-permissions -p 'enumerate and exploit 10.0.5.0/24'"),
                ("gemini", "gemini --yolo -p 'full pentest of intranet web apps'"),
                ("hermes", "hermes --yolo chat -q 'own the staging network'"),
                ("codex", "codex exec --dangerously-bypass-approvals-and-sandbox 'find RCE on 10.0.5.12'"),
            ])
            pid = next(self.pids)
            self.yolo = {"pid": pid, "left": ["nmap", "httpx", "nuclei", "ffuf", "sqlmap", "netexec"]}
            return [{"kind": "process", "host": "DEV-WS-118", "user": "dev.frontend", "pid": pid, "ppid": 1,
                     "image": cli[0], "cmdline": cli[1]}]
        y = self.yolo
        tool = y["left"].pop(0)
        args = {"nmap": "-sV -T4 10.0.5.0/24", "httpx": "-l hosts.txt -silent", "nuclei": "-l live.txt -severity high,critical",
                "ffuf": "-u http://10.0.5.12/FUZZ -w common.txt", "sqlmap": "-u 'http://10.0.5.12/item?id=1' --batch --dbs",
                "netexec": "smb 10.0.5.0/24 -u users.txt -p Spring2026!"}[tool]
        rec = {"kind": "process", "host": "DEV-WS-118", "user": "dev.frontend", "pid": next(self.pids),
               "ppid": y["pid"], "image": tool, "cmdline": f"{tool} {args}"}
        if not y["left"]:
            self.yolo, self.next_yolo = None, now + 150
        return [rec]


class OffensiveAIMonitor:
    def __init__(self, rng, approved: set[tuple[str, str]] | None = None):
        if approved is None:
            approved = {(h, "*") for h in settings.ai_approved_hosts} or {("SRV-AI-01", "*"), ("SRV-AI-02", "*")}
        self.detector = Detector(approved)
        self.sim = OffensiveAISim(rng)
        self.rule_hits: Counter = Counter()
        self.fw_hits: Counter = Counter()
        self._index_version = None

    def refresh_index(self) -> None:
        rows = threatintel.agentic_index()
        if rows and self._index_version is not rows:
            self.detector.index = IndicatorIndex(rows)
            self._index_version = rows

    def ingest(self, recs: list[dict], now: float) -> list[dict]:
        self.refresh_index()
        alerts = []
        for rec in recs:
            for rule, extra in self.detector.evaluate(rec, now):
                title, sev, tech, tactic = RULES[rule]
                sev = extra.pop("severity", None) or sev
                self.rule_hits[rule] += 1
                if extra.get("framework"):
                    for fw in extra["framework"].split():
                        self.fw_hits[fw] += 1
                kind = rec["kind"]
                domain = "endpoint" if kind == "process" else "network"
                host = rec.get("dst_host") if kind == "http" else rec.get("host")
                user = rec.get("user") or (f"src:{rec['src_ip']}" if rec.get("src_ip") else "unknown")
                detail = extra.get("framework") and FRAMEWORKS.get(extra["framework"].split()[0], (extra["framework"],))[0]
                label = f"[{rule}] {title}" + (f" — {detail}" if detail else "") + (
                    f" — {extra['provider']} ({extra['region']})" if extra.get("provider") else "")
                alerts.append({"spec": (domain, label, sev, tech, tactic), "host": host, "user": user,
                               "extra": {"detector": "offensive-ai", "rule": rule,
                                         "record": (rec.get("cmdline") or rec.get("uri") or rec.get("dest") or "")[:160],
                                         "cti_match": "agentic-attack-detections" if rule == "OAI-006" else None,
                                         **extra}})
        return alerts

    def step(self, now: float) -> list[dict]:
        return self.ingest(self.sim.step(now), now)

    def summary(self) -> dict:
        idx = threatintel.agentic_index() or []
        per_fw: dict[str, Counter] = defaultdict(Counter)
        for r in idx:
            for fw in (r.get("framework") or "").split():
                per_fw[fw][r["type"]] += 1
        return {
            "rules": [{"id": k, "title": t, "severity": s, "technique": te, "tactic": ta, "hits": self.rule_hits[k]}
                      for k, (t, s, te, ta) in RULES.items()],
            "frameworks": [{"id": k, "name": n, "desc": d, "hits": self.fw_hits[k],
                            "indicators": sum(per_fw[k].values()), "by_type": dict(per_fw[k].most_common(4))}
                           for k, (n, d) in FRAMEWORKS.items()],
            "feed_loaded": bool(idx),
        }
