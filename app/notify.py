"""Push incident alerts to chat / email so the SOC does not have to watch the dashboard.

Channels (all optional, configured by environment variables — secrets never live in the repo):
  SOC_NOTIFY_TEAMS_URL      Microsoft Teams Workflows ("When a Teams webhook request is received") URL — Adaptive Card
  SOC_NOTIFY_SLACK_URL      Slack incoming webhook URL
  SOC_NOTIFY_LINE_TOKEN     LINE Messaging API channel access token  +  SOC_NOTIFY_LINE_TO (user / group / room id)
  SOC_NOTIFY_WEBHOOK_URL    any HTTPS endpoint; receives the incident summary as JSON
  SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SOC_NOTIFY_EMAIL_TO (comma-separated)
Behaviour:
  SOC_NOTIFY_MIN_SEVERITY   high (default) | critical | medium
  SOC_NOTIFY_SIMULATED      off (default): only incidents built from real ingested logs are sent
  SOC_NOTIFY_REDACT         off (default) | on: mask user names (PDPA data minimisation for third-party chat)
  SOC_PUBLIC_URL            e.g. https://soc.example.com — adds a dashboard link to each message
  SOC_NOTIFY_MAX_PER_10MIN  20 (default): beyond this, one summary message instead of a flood
  SOC_NOTIFY_DEBOUNCE       10 (seconds, default): changes to one incident inside this window go out as one message

An incident is sent when it first reaches the minimum severity, and again only if it escalates.
"""
import asyncio
import os
import smtplib
import time
from collections import deque
from email.message import EmailMessage

import httpx

SEV = ["info", "low", "medium", "high", "critical"]
EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


class Notifier:
    def __init__(self):
        self.reload()
        self.pending: dict[int, dict] = {}  # incident id -> live incident (latest state is sent)
        self.rule_pending: dict[int, tuple[dict, set]] = {}  # from notification rules: incident -> chosen channels
        self.wake: asyncio.Event | None = None
        self.task: asyncio.Task | None = None
        self.sent_times: deque = deque()
        self.suppressed = 0
        self.history: deque = deque(maxlen=50)  # recent delivery results (no secrets)

    def reload(self) -> None:
        self.teams = _env("SOC_NOTIFY_TEAMS_URL")
        self.slack = _env("SOC_NOTIFY_SLACK_URL")
        self.line_token, self.line_to = _env("SOC_NOTIFY_LINE_TOKEN"), _env("SOC_NOTIFY_LINE_TO")
        self.webhook = _env("SOC_NOTIFY_WEBHOOK_URL")
        self.smtp = {k: _env(k) for k in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM")}
        self.email_to = [x.strip() for x in _env("SOC_NOTIFY_EMAIL_TO").split(",") if x.strip()]
        sev = _env("SOC_NOTIFY_MIN_SEVERITY", "high").lower()
        self.min_sev = sev if sev in SEV else "high"
        self.include_simulated = _env("SOC_NOTIFY_SIMULATED", "off").lower() in ("on", "1", "true", "yes")
        self.redact = _env("SOC_NOTIFY_REDACT", "off").lower() in ("on", "1", "true", "yes")
        self.public_url = _env("SOC_PUBLIC_URL").rstrip("/")
        self.max_per_10min = int(_env("SOC_NOTIFY_MAX_PER_10MIN", "20") or 20)
        self.debounce = float(_env("SOC_NOTIFY_DEBOUNCE", "10") or 10)

    def channels(self) -> list[str]:
        out = []
        if self.teams:
            out.append("teams")
        if self.slack:
            out.append("slack")
        if self.line_token and self.line_to:
            out.append("line")
        if self.webhook:
            out.append("webhook")
        if self.smtp["SMTP_HOST"] and self.smtp["SMTP_FROM"] and self.email_to:
            out.append("email")
        return out

    def status(self) -> dict:
        return {"channels": self.channels(), "min_severity": self.min_sev, "include_simulated": self.include_simulated,
                "redact_users": self.redact, "public_url": bool(self.public_url), "suppressed": self.suppressed,
                "recent": list(self.history)[-10:]}

    # ---------- decision ----------
    def should_send(self, inc: dict) -> bool:
        if not self.channels():
            return False
        if not inc.get("real") and not self.include_simulated:
            return False
        sev = SEV.index(inc.get("severity", "info"))
        if sev < SEV.index(self.min_sev):
            return False
        return sev > inc.get("notified_sev", -1)

    def offer(self, inc: dict) -> bool:
        """Called by the engine when an incident changes. Queues at most one message per severity level."""
        if not self.should_send(inc) or self.wake is None:
            return False
        inc["notified_sev"] = SEV.index(inc["severity"])
        if len(self.pending) >= 500 and inc["id"] not in self.pending:
            self.suppressed += 1
            return False
        self.pending[inc["id"]] = inc  # coalesced: the flush sends whatever state it has by then
        self.wake.set()
        return True

    def queue_rule(self, inc: dict, channels: list[str]) -> bool:
        """A tenant notification rule matched: send this incident to the rule's channels (if configured here)."""
        chans = set(channels) & set(self.channels())
        if not chans or self.wake is None:
            return False
        prev = self.rule_pending.get(inc["id"], (inc, set()))[1]
        self.rule_pending[inc["id"]] = (inc, prev | chans)
        self.wake.set()
        return True

    def summary(self, inc: dict) -> dict:
        alerts = inc.get("alerts", [])
        users = inc.get("users", [])
        if self.redact:
            users = [u[:2] + "***" if not u.startswith(("src:", "svc.")) else u for u in users]
        rules = sorted({a.get("rule") for a in alerts if a.get("rule")})
        return {
            "id": inc["id"], "title": inc.get("title"), "severity": inc.get("severity"), "status": inc.get("status"),
            "coordinated": inc.get("coordinated", False), "real": inc.get("real", False),
            "hosts": inc.get("hosts", [])[:10], "users": users[:10], "domains": inc.get("domains", []),
            "tactics": inc.get("tactics", []), "rules": rules, "alerts": len(alerts),
            "first_seen": inc.get("first_ts"), "last_seen": inc.get("last_ts"),
            "latest": (alerts[-1].get("title") if alerts else None),
            "url": f"{self.public_url}/soc#inc-{inc['id']}" if self.public_url else None,
        }

    # ---------- formatting ----------
    @staticmethod
    def text(s: dict) -> str:
        t = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(s["last_seen"] or time.time()))
        lines = [f"{EMOJI.get(s['severity'], '')} [{s['severity'].upper()}] SOC Incident #{s['id']}",
                 f"{s['title']}",
                 f"เครื่อง: {', '.join(s['hosts']) or '-'}",
                 f"ผู้ใช้/บัญชี: {', '.join(s['users']) or '-'}",
                 f"โดเมน: {', '.join(s['domains'])} · {s['alerts']} alerts" + (" · หลายโดเมน (coordinated)" if s["coordinated"] else ""),
                 f"Rules: {', '.join(s['rules']) or '-'}",
                 f"ล่าสุด: {s['latest'] or '-'} ({t})"]
        if not s["real"]:
            lines.insert(1, "⚠️ ข้อมูลจำลอง (demo)")
        if s["url"]:
            lines.append(f"เปิดดู: {s['url']}")
        return "\n".join(lines)

    def teams_card(self, s: dict) -> dict:
        facts = [{"title": k, "value": v} for k, v in (
            ("Severity", s["severity"].upper()), ("Hosts", ", ".join(s["hosts"]) or "-"),
            ("Users", ", ".join(s["users"]) or "-"), ("Domains", ", ".join(s["domains"])),
            ("Rules", ", ".join(s["rules"]) or "-"), ("Alerts", str(s["alerts"])), ("Latest", s["latest"] or "-"))]
        body = [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": True,
                 "color": "Attention" if s["severity"] in ("critical", "high") else "Warning",
                 "text": f"{EMOJI.get(s['severity'], '')} SOC Incident #{s['id']}: {s['title']}"},
                {"type": "FactSet", "facts": facts}]
        if not s["real"]:
            body.insert(1, {"type": "TextBlock", "text": "ข้อมูลจำลอง (demo)", "isSubtle": True})
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.4", "body": body}
        if s["url"]:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "เปิดใน SOC Dashboard", "url": s["url"]}]
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                    "content": card}]}

    # ---------- delivery ----------
    async def _post(self, client: httpx.AsyncClient, name: str, url: str, payload: dict, headers: dict | None = None):
        for attempt in range(3):
            try:
                r = await client.post(url, json=payload, headers=headers or {})
                if r.status_code < 300:
                    return name, True, r.status_code
                if r.status_code not in (429, 500, 502, 503, 504):
                    return name, False, r.status_code
            except httpx.HTTPError as e:
                if attempt == 2:
                    return name, False, type(e).__name__
            await asyncio.sleep(2 ** attempt)
        return name, False, "retries exhausted"

    def _email(self, s: dict) -> tuple[str, bool, str]:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[SOC {s['severity'].upper()}] Incident #{s['id']}: {s['title']}"
            msg["From"] = self.smtp["SMTP_FROM"]
            msg["To"] = ", ".join(self.email_to)
            msg.set_content(self.text(s))
            with smtplib.SMTP(self.smtp["SMTP_HOST"], int(self.smtp["SMTP_PORT"] or 587), timeout=20) as srv:
                srv.starttls()
                if self.smtp["SMTP_USER"]:
                    srv.login(self.smtp["SMTP_USER"], self.smtp["SMTP_PASSWORD"])
                srv.send_message(msg)
            return "email", True, "sent"
        except (OSError, smtplib.SMTPException) as e:
            return "email", False, type(e).__name__

    async def deliver(self, s: dict, only: set | None = None) -> list[tuple]:
        """Send to every configured channel, or only to those in `only` (notification rules pick channels)."""
        text = self.text(s)
        jobs = []
        want = (lambda ch: only is None or ch in only)
        async with httpx.AsyncClient(timeout=15) as client:
            if self.teams and want("teams"):
                jobs.append(self._post(client, "teams", self.teams, self.teams_card(s)))
            if self.slack and want("slack"):
                jobs.append(self._post(client, "slack", self.slack, {"text": text}))
            if self.line_token and self.line_to and want("line"):
                jobs.append(self._post(client, "line", "https://api.line.me/v2/bot/message/push",
                                       {"to": self.line_to, "messages": [{"type": "text", "text": text[:4900]}]},
                                       {"Authorization": f"Bearer {self.line_token}"}))
            if self.webhook and want("webhook"):
                jobs.append(self._post(client, "webhook", self.webhook, {"event": "soc.incident", "incident": s}))
            results = list(await asyncio.gather(*jobs))
        if "email" in self.channels() and want("email"):
            results.append(await asyncio.to_thread(self._email, s))
        self.history.append({"ts": time.time(), "incident": s["id"], "severity": s["severity"],
                             "results": {n: ("ok" if ok else f"failed ({detail})") for n, ok, detail in results}})
        return results

    async def _run(self) -> None:
        while True:
            await self.wake.wait()
            await asyncio.sleep(self.debounce)
            self.wake.clear()
            batch, self.pending = list(self.pending.values()), {}
            ruled, self.rule_pending = self.rule_pending, {}
            for inc in batch:
                await self._send_one(self.summary(inc))
            for inc_id, (inc, chans) in ruled.items():
                if not any(i["id"] == inc_id for i in batch):  # already sent to every channel above
                    await self._send_one(self.summary(inc), chans)

    async def _send_one(self, s: dict, only: set | None = None) -> None:
        now = time.time()
        while self.sent_times and now - self.sent_times[0] > 600:
            self.sent_times.popleft()
        if len(self.sent_times) >= self.max_per_10min:
            self.suppressed += 1
            return
        if self.suppressed:  # tell people messages were held back, then carry on
            s = {**s, "latest": f"{s['latest']} · (มีอีก {self.suppressed} incident ที่ไม่ได้ส่งเพราะเกินเพดานการแจ้งเตือน)"}
            self.suppressed = 0
        self.sent_times.append(now)
        try:
            await (self.deliver(s) if only is None else self.deliver(s, only))
        except Exception as e:  # noqa: BLE001 - never let a bad channel kill the loop
            self.history.append({"ts": now, "incident": s.get("id"), "error": type(e).__name__})

    def start(self) -> None:
        if self.task is None or self.task.done():
            self.wake = asyncio.Event()
            self.task = asyncio.create_task(self._run())

    def stop(self) -> None:
        if self.task and not self.task.done():
            self.task.cancel()
        self.task = None


notifier = Notifier()
