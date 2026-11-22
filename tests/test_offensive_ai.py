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
