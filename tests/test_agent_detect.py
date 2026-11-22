import random

from app import agent_detect as ad
from app.modules import threatintel


def rec(kind, agent="support-copilot", session="S-1", ts=100.0, **kw):
    return {"id": 1, "ts": ts, "agent": agent, "session": session, "kind": kind, "decision": "allowed",
            "summary": kw.pop("summary", kind), **kw}


def mon():
    return ad.AgentMonitor(random.Random(0))


def rules_of(m, *recs, now=100.0):
    m.ingest(list(recs), now)
    return [r for x in recs for r in x["rules"]]


def test_scope_secret_and_injection_chain():
    m = mon()
    hits = rules_of(m, rec("prompt", flags=["instruction_override"]),
                    rec("tool_call", tool="files.read", args="/srv/app/.env"))
    assert hits == ["AGT-007", "AGT-001", "AGT-004", "AGT-008"]
    # policy gateway denies out-of-scope tools; same rule doesn't refire in the session
    r2 = rec("tool_call", tool="files.read", args="/etc/x")
    assert rules_of(m, r2) == [] and r2["decision"] == "denied"


def test_benign_in_scope_calls_are_quiet():
    m = mon()
    assert rules_of(m, rec("tool_call", tool="kb.search", args="q=vpn", bytes=100),
                    rec("network", dest="api.internal.corp", ip="10.0.0.5")) == []


def test_shell_egress_c2_and_exfil(monkeypatch):
    monkeypatch.setattr(threatintel, "c2_ips", lambda: ["198.51.100.7"])
    m = mon()
    assert rules_of(m, rec("process", image="powershell.exe", pid=2, ppid=1)) == ["AGT-003"]
    assert rules_of(m, rec("process", agent="devops-agent", image="bash", pid=3, ppid=1)) == []
    assert rules_of(m, rec("network", dest="198.51.100.7", ip="198.51.100.7")) == ["AGT-006"]
    assert rules_of(m, rec("network", agent="finance-rpa", session="S-2", dest="x.example", ip="1.1.1.1")) == ["AGT-005"]
    hits = rules_of(m, rec("tool_call", agent="finance-rpa", session="S-3", tool="erp.read", args="all", bytes=9_000_000),
                    rec("tool_call", agent="finance-rpa", session="S-3", tool="email.send", args="to=a@ext.example",
                        dest="ext.example"))
    assert hits == ["AGT-009"]
    assert m.agents["finance-rpa"]["status"] == "compromised"


def test_rate_anomaly_and_role_change():
    m = mon()
    recs = [rec("tool_call", agent="soc-triage", tool="siem.query", args="q", ts=100 + i * 0.5) for i in range(30)]
    assert rules_of(m, *recs) == ["AGT-010"]
    assert rules_of(m, rec("auth", session="S-9", action="role_assign", scope="Directory.Read.All")) == ["AGT-002"]


def test_contain_blocks_and_hunt():
    m = mon()
    m.contain("support-copilot")
    r = rec("tool_call", tool="files.read", args="/srv/app/.env")
    assert rules_of(m, r) == [] and r["decision"] == "blocked"
    m.ingest([rec("tool_call", agent="devops-agent", session="S-5", tool="shell.exec", args="kubectl get pods",
                  summary="shell.exec(kubectl)")], 101)
    assert len(m.hunt("agent:devops tool:shell")) == 1
    assert len(m.hunt("decision:blocked")) == 1
    assert m.hunt("-agent:devops kubectl") == []


def test_simulated_kill_chain_end_to_end():
    m = mon()
    t = 1000.0
    for i in range(3000):
        m.step(t + i)
    fired = {r for r, n in m.rule_hits.items() if n}
    assert {"AGT-007", "AGT-001", "AGT-004", "AGT-003", "AGT-005", "AGT-002"} <= fired
    sess = next(r["session"] for r in m.records if r["kind"] == "prompt")
    detail = m.session(sess)
    assert detail["processes"][0]["image"] == "agent-runtime"
    assert all(r["simulated"] for r in m.records)


def test_mcp_policy():
    m = mon()
    m.agents["support-copilot"]["mcp_servers"] = ["kb-server"]
    r1 = rec("tool_call", tool="mcp__kb-server__search", mcp_server="kb-server")
    r2 = rec("tool_call", session="S-2", tool="mcp__github__push", mcp_server="github")
    r3 = rec("tool_call", agent="devops-agent", session="S-3", tool="mcp__hexstrike-ai__nmap_scan", mcp_server="hexstrike-ai")
    alerts = m.ingest([r1, r2, r3], 100.0)
    assert "AGT-012" not in r1["rules"] and "AGT-012" in r2["rules"] and "AGT-012" in r3["rules"]
    sev = {a["extra"]["mcp_server"]: a["spec"][2] for a in alerts if a["extra"]["rule"] == "AGT-012"}
    assert sev == {"github": "high", "hexstrike-ai": "critical"}
