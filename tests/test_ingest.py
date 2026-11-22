import json

import pytest

from app import ingest, telemetry

NOW = 1_800_000_000.0


def test_native_clean_and_reject():
    recs, rej = ingest.parse(json.dumps([
        {"kind": "process", "host": "H1", "pid": "10", "ppid": 1, "image": "nmap", "cmdline": "nmap -sV x"},
        {"kind": "net", "host": "SRV-A", "dest": "https://api.deepseek.com/v1/chat", "ts": "2026-11-22T01:00:00Z"},
        {"kind": "bogus"}, {"kind": "http"}, "not-a-dict",
    ]).encode(), "native", now=NOW)
    assert rej == 3 and recs[0]["pid"] == 10 and recs[1]["dest"] == "api.deepseek.com"
    assert recs[1]["ts"] != NOW and all(r["simulated"] is False for r in recs)


def test_ndjson_and_agent_records():
    body = "\n".join(json.dumps(x) for x in [
        {"agent": "hr-bot", "kind": "tool_call", "tool": "files.read", "args": "/home/a/.env"},
        {"agent": "hr-bot", "kind": "net", "dest": "x.example", "dest_ip": "198.51.100.9"},
    ]).encode()
    recs, rej = ingest.parse(body, "auto", now=NOW)
    assert rej == 0 and recs[0]["session"] == "ext-hr-bot" and recs[1]["kind"] == "network" and recs[1]["ip"] == "198.51.100.9"


def test_ecs_mapping():
    docs = [
        {"@timestamp": "2026-11-22T02:00:00Z", "event": {"category": ["process"], "type": ["start"]},
         "host": {"name": "DEV-1"}, "user": {"name": "dev"},
         "process": {"pid": 5, "executable": "/usr/bin/nuclei", "command_line": "nuclei -l x",
                     "parent": {"pid": 4, "name": "claude", "command_line": "claude --dangerously-skip-permissions"}}},
        {"@timestamp": "2026-11-22T02:00:01Z", "event.category": "network", "host.name": "SRV-2",
         "dns.question.name": "open.bigmodel.cn"},
        {"@timestamp": "2026-11-22T02:00:02Z", "event": {"category": ["web"]}, "host": {"name": "WEB"},
         "source": {"ip": "203.0.113.5"}, "http": {"request": {"method": "GET"}, "response": {"status_code": 404}},
         "url": {"path": "/.env"}, "user_agent": {"original": "HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)"}},
        {"@timestamp": "2026-11-22T02:00:03Z", "event": {"category": ["process"], "type": ["end"]}, "host": {"name": "X"}},
    ]
    recs, rej = ingest.parse(json.dumps(docs).encode(), "ecs", now=NOW)
    assert rej == 1 and [r["kind"] for r in recs] == ["process", "net", "http"]
    assert recs[0]["parent_cmdline"].startswith("claude") and recs[1]["dest"] == "open.bigmodel.cn"
    assert recs[2]["status"] == 404 and recs[2]["uri"] == "/.env"


def test_defender_mapping():
    rows = {"records": [
        {"Timestamp": "2026-11-22T03:00:00Z", "DeviceName": "dev-7", "ActionType": "ProcessCreated", "FileName": "sqlmap",
         "ProcessCommandLine": "sqlmap -u x", "ProcessId": 9, "InitiatingProcessId": 8,
         "InitiatingProcessFileName": "gemini", "InitiatingProcessCommandLine": "gemini --yolo -p hack"},
        {"Timestamp": "2026-11-22T03:00:01Z", "DeviceName": "SRV-FS", "RemoteUrl": "dashscope.aliyuncs.com",
         "RemoteIP": "1.2.3.4", "RemotePort": 443},
        {"Timestamp": "2026-11-22T03:00:02Z", "DeviceName": "x", "ActionType": "LogonSuccess"},
    ]}
    recs, rej = ingest.parse(json.dumps(rows).encode(), "auto", now=NOW)
    assert rej == 1 and recs[0]["parent_image"] == "gemini" and recs[1]["port"] == 443


def test_access_log():
    lines = ('203.0.113.7 - - [22/Nov/2026:10:00:00 +0700] "GET /.git/config HTTP/1.1" 404 12 "-" '
             '"Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)"\ngarbage line\n')
    recs, rej = ingest.parse(lines.encode(), "access_log", host="SRV-WEB-01", now=NOW)
    assert rej == 1 and recs[0]["dst_host"] == "SRV-WEB-01" and recs[0]["status"] == 404 and "CyberStrikeAI" in recs[0]["ua"]


def test_limits_and_errors():
    with pytest.raises(ingest.IngestError):
        ingest.parse(b"{not json", "native")
    with pytest.raises(ingest.IngestError):
        ingest.parse(b"[]", "xml")
    with pytest.raises(ingest.IngestError):
        ingest.parse(json.dumps([{}] * (ingest.MAX_RECORDS + 1)).encode(), "native")


def test_engine_real_only_mode_detects_and_tracks_shadow_ai():
    e = telemetry.Engine(seed=1, simulate=False)
    assert e.endpoints == {} and e.agents.agents == {} and e.step(NOW) == []
    recs, _ = ingest.parse(json.dumps([
        {"kind": "process", "host": "DEV-9", "pid": 2, "ppid": 1, "image": "nmap",
         "parent_image": "claude", "parent_cmdline": "claude --dangerously-skip-permissions -p x", "ts": NOW},
        {"kind": "net", "host": "SRV-FS", "dest": "api.deepseek.com", "ts": NOW},
        {"agent": "hr-bot", "kind": "tool_call", "tool": "files.read", "args": "/srv/.env", "ts": NOW},
    ]).encode(), "native", now=NOW)
    r = e.ingest_external(recs)
    assert r["alerts_by_rule"] == {"OAI-001": 1, "OAI-002": 1, "AGT-011": 1, "AGT-004": 1}
    assert "DEV-9" in e.endpoints and e.agents.agents["hr-bot"]["registered"] is False
    out = e.step(NOW + 1)  # ingested events are broadcast once, then cleared
    assert len(out) == 4 and all(ev["simulated"] is False and ev["src_country"] is None for ev in out)
    assert e.step(NOW + 2) == [] and e.stats(NOW)["mode"] == {"simulation": False, "ingested": 3, "restored": 0}


def test_registered_agent_scopes_apply():
    e = telemetry.Engine(seed=1, simulate=False)
    e.agents.register([{"id": "hr-bot", "host": "SRV-HR", "account": "svc.hr", "scopes": ["hr.read"],
                        "egress": ["api.internal.corp"], "shell": False}])
    recs, _ = ingest.parse(json.dumps([
        {"agent": "hr-bot", "kind": "tool_call", "tool": "hr.read", "args": "employee=1", "ts": NOW},
        {"agent": "hr-bot", "kind": "tool_call", "tool": "shell.exec", "args": "id", "ts": NOW, "session": "s2"},
        {"agent": "hr-bot", "kind": "process", "image": "bash", "pid": 3, "ppid": 1, "ts": NOW, "session": "s2"},
    ]).encode(), "native", now=NOW)
    r = e.ingest_external(recs)
    assert r["alerts_by_rule"] == {"AGT-001": 1, "AGT-003": 1}
    assert recs[1]["decision"] == "denied"


def test_session_view_for_real_unregistered_agent():
    e = telemetry.Engine(seed=1, simulate=False)
    recs, _ = ingest.parse(json.dumps([
        {"agent": "x-bot", "kind": "process", "image": "bash", "pid": 7, "ppid": 3, "session": "s1", "ts": NOW},
        {"agent": "x-bot", "kind": "tool_call", "tool": "kb.search", "session": "s1", "ts": NOW}]).encode(), "native", now=NOW)
    e.ingest_external(recs)
    d = e.agents.session("s1")
    assert d["agent"]["scopes"] is None and [p["image"] for p in d["processes"]] == ["bash"]


def test_wildcard_ai_approval():
    from app import offensive_ai as oa
    d = oa.Detector({("SRV-AI-09", "*")})
    assert d.evaluate({"kind": "net", "host": "SRV-AI-09", "dest": "api.deepseek.com"}, 0) == []
    assert d.evaluate({"kind": "net", "host": "SRV-OTHER", "dest": "api.deepseek.com"}, 0)[0][0] == "OAI-002"


def test_new_kinds_and_mappings():
    recs, rej = ingest.parse(json.dumps([
        {"kind": "logon", "dest_host": "SRV-1", "src_host": "WS-1", "user": "a", "event_id": "4624", "logon_type": "3"},
        {"kind": "db", "host": "SQL-1", "user": "u", "statement": "select 1", "rows": "5"},
        {"kind": "dlp", "user": "u", "dest": "https://share.example/x", "bytes": 10},
        {"kind": "db", "host": "SQL-1"},
        {"agent": "a1", "kind": "tool_call", "tool": "mcp__hexstrike-ai__nmap_scan"},
        {"DeviceName": "SRV-9", "ActionType": "LogonSuccess", "LogonType": "Network", "RemoteDeviceName": "WS-4",
         "RemoteIP": "10.0.0.4", "AccountName": "it.admin"},
        {"@timestamp": "2026-11-22T00:00:00Z", "event": {"category": ["authentication"], "code": "4624"},
         "host": {"name": "SRV-8"}, "source": {"ip": "10.0.0.7"}, "user": {"name": "x"},
         "winlog": {"event_data": {"LogonType": "3"}}},
    ]).encode(), "auto", now=NOW)
    assert rej == 1
    kinds = [r["kind"] for r in recs]
    assert kinds == ["logon", "db", "dlp", "tool_call", "logon", "logon"]
    assert recs[0]["event_id"] == 4624 and recs[2]["dest"] == "share.example" and recs[3]["mcp_server"] == "hexstrike-ai"
    assert recs[4]["logon_type"] == 3 and recs[4]["src_host"] == "WS-4" and recs[5]["logon_type"] == 3


def test_unknown_users_do_not_merge_hosts():
    e = telemetry.Engine(seed=1, simulate=False)
    recs, _ = ingest.parse(json.dumps([{"kind": "net", "host": h, "dest": "api.deepseek.com", "ts": NOW}
                                       for h in ("SRV-A", "SRV-B")]).encode(), "native", now=NOW)
    e.ingest_external(recs)
    assert len(e.incidents) == 2
