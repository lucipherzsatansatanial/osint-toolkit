import asyncio
import json

import httpx
import respx

from app import ingest, telemetry
from app.notify import Notifier

NOW = 1_800_000_000.0
INC = {"id": 1001, "title": "[OAI-001] AI agent CLI with approvals disabled", "severity": "critical", "status": "open",
       "real": True, "hosts": ["DEV-9"], "users": ["somchai.k", "svc.web", "src:203.0.113.5"], "domains": ["endpoint"],
       "tactics": ["Execution"], "first_ts": NOW, "last_ts": NOW,
       "alerts": [{"rule": "OAI-001", "title": "x"}, {"rule": "OAI-003", "title": "fan-out"}]}


def make(monkeypatch, **env):
    base = {"SOC_NOTIFY_TEAMS_URL": "https://teams.example/hook", "SOC_NOTIFY_SLACK_URL": "https://slack.example/hook",
            "SOC_NOTIFY_LINE_TOKEN": "tok", "SOC_NOTIFY_LINE_TO": "Cgroup", "SOC_NOTIFY_WEBHOOK_URL": "https://wh.example/x",
            "SOC_PUBLIC_URL": "https://soc.example/", "SOC_NOTIFY_DEBOUNCE": "0.01"}
    for k, v in {**base, **env}.items():
        monkeypatch.setenv(k, v)
    return Notifier()


def test_should_send_rules(monkeypatch):
    n = make(monkeypatch)
    assert n.channels() == ["teams", "slack", "line", "webhook"]
    assert n.should_send(dict(INC))
    assert not n.should_send({**INC, "real": False})                  # simulated off by default
    assert not n.should_send({**INC, "severity": "medium"})           # below threshold
    assert not n.should_send({**INC, "notified_sev": 4})              # already sent at this level
    assert n.should_send({**INC, "notified_sev": 3})                  # escalated high -> critical
    assert not Notifier().should_send(dict(INC)) or Notifier().channels()  # no channels -> never


def test_summary_text_card_and_redaction(monkeypatch):
    n = make(monkeypatch, SOC_NOTIFY_REDACT="on")
    s = n.summary(INC)
    assert s["users"] == ["so***", "svc.web", "src:203.0.113.5"] and s["url"] == "https://soc.example/soc#inc-1001"
    assert s["rules"] == ["OAI-001", "OAI-003"]
    t = n.text(s)
    assert "[CRITICAL] SOC Incident #1001" in t and "somchai" not in t and "ข้อมูลจำลอง" not in t
    card = n.teams_card(s)["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and card["actions"][0]["url"].endswith("#inc-1001")


@respx.mock
async def test_deliver_all_channels(monkeypatch):
    n = make(monkeypatch)
    routes = {name: respx.post(url).mock(return_value=httpx.Response(code)) for name, url, code in [
        ("teams", "https://teams.example/hook", 202), ("slack", "https://slack.example/hook", 200),
        ("line", "https://api.line.me/v2/bot/message/push", 200), ("webhook", "https://wh.example/x", 400)]}
    res = {name: ok for name, ok, _ in await n.deliver(n.summary(INC))}
    assert res == {"teams": True, "slack": True, "line": True, "webhook": False}
    line_req = routes["line"].calls[0].request
    assert line_req.headers["authorization"] == "Bearer tok" and json.loads(line_req.content)["to"] == "Cgroup"
    assert n.status()["recent"][-1]["results"]["webhook"].startswith("failed")
    assert "tok" not in json.dumps(n.status())  # status never leaks secrets


async def test_engine_offers_once_per_severity_and_rate_limit(monkeypatch):
    n = make(monkeypatch, SOC_NOTIFY_MAX_PER_10MIN="1")
    sent = []

    async def fake_deliver(s):
        sent.append(s)
        return []
    n.deliver = fake_deliver
    n.start()
    e = telemetry.Engine(seed=1, simulate=False)
    e.on_incident = n.offer
    recs, _ = ingest.parse(json.dumps([
        {"kind": "process", "host": "DEV-9", "pid": 2, "ppid": 1, "image": "nmap", "parent_image": "claude",
         "parent_cmdline": "claude --dangerously-skip-permissions", "ts": NOW},
        {"kind": "net", "host": "SRV-X", "dest": "api.deepseek.com", "ts": NOW},
        {"kind": "net", "host": "SRV-Y", "dest": "api.deepseek.com", "ts": NOW},
    ]).encode(), "native", now=NOW)
    e.ingest_external(recs)
    await asyncio.sleep(0.05)
    n.stop()
    assert len(sent) == 1 and n.suppressed == 2  # 3 high incidents, cap of 1 per 10 min
    assert all(i.get("notified_sev") == 3 for i in e.incidents.values())


async def test_updates_inside_debounce_window_are_one_message(monkeypatch):
    n = make(monkeypatch, SOC_NOTIFY_DEBOUNCE="0.05")
    sent = []

    async def fake_deliver(s):
        sent.append(s)
        return []
    n.deliver = fake_deliver
    n.start()
    inc = {**INC, "severity": "high", "alerts": [{"rule": "OAI-001", "title": "a"}]}
    assert n.offer(inc)
    inc.update(severity="critical", alerts=inc["alerts"] + [{"rule": "OAI-005", "title": "chain"}])
    assert n.offer(inc)  # escalation inside the window
    await asyncio.sleep(0.15)
    n.stop()
    assert len(sent) == 1 and sent[0]["severity"] == "critical" and sent[0]["rules"] == ["OAI-001", "OAI-005"]
