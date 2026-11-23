"""Demo approval queue for the simulated (demo) tenant.

The demo SOC team (*.demo accounts) files the requests a real team would, driven by what the simulator actually does:
- response requests: "contain agent X" when a simulated AI agent raises a high/critical AGT-* alert, and
  "release agent X" some time after it was contained;
- agent-permission requests: new demo agents and scope / egress / shell changes to existing demo agents.

Requests that nobody handles are decided by lead.demo after a while, so the queue shows both pending and decided
items. A user with the right permission can approve or reject pending demo requests to practise four-eyes; the
effect stays inside the simulator (demo agents only, in memory).

Like demo tasks: memory only, negative ids, `simulated: True`, never in a customer tenant.
"""
import random

ANALYSTS = ["somchai.demo", "nok.demo", "pim.demo", "arthit.demo", "kanya.demo"]
LEAD = "lead.demo"
CAP = 40
EXTRA_SCOPES = ["calendar.read", "crm.read", "ticket.close", "report.export", "file.read", "kb.update", "email.send"]
EXTRA_EGRESS = ["api.partner.example", "storage.vendor.example", "translate.saas.example"]
NEW_AGENTS = [
    {"id": "hr-assistant", "owner": "hr.ops", "host": "SRV-AI-02", "account": "svc.ai.hr",
     "scopes": ["hr.read", "kb.search", "email.read"], "egress": ["hr.internal.corp"], "shell": False},
    {"id": "legal-summarizer", "owner": "legal.team", "host": "SRV-AI-02", "account": "svc.ai.legal",
     "scopes": ["docs.read", "kb.search"], "egress": ["docs.internal.corp"], "shell": False},
    {"id": "soc-triage-bot", "owner": "soc.team", "host": "SRV-AI-01", "account": "svc.ai.soctriage",
     "scopes": ["alerts.read", "ticket.update"], "egress": ["api.internal.corp"], "shell": False},
]


def _state(eng):
    if not hasattr(eng, "_dreq"):
        eng._dreq = {"resp": {}, "ag": {}, "seq": 0, "alerts": set(), "next_ag": 0.0, "contained": {},
                     "rng": random.Random(f"demo-requests:{eng.tenant}")}
    return eng._dreq


def _new(st, box: str, body: dict, at: float) -> dict:
    st["seq"] -= 1
    r = {"id": st["seq"], **body, "requested_by": st["rng"].choice(ANALYSTS), "requested_at": at, "status": "pending",
         "simulated": True, "_auto_at": at + st["rng"].uniform(20, 60) * 60}
    st[box][r["id"]] = r
    return r


def apply(eng, box: str, r: dict) -> dict | None:
    """Carry out an approved demo request inside the simulator."""
    if box == "resp":
        ag = eng.agents.agents.get(r["agent"])
        if ag is None:
            return None
        out = eng.agents.contain(r["agent"], r["action"] == "contain")
        if r["action"] == "contain":
            _state(eng)["contained"][r["agent"]] = r.get("decided_at")
        else:
            _state(eng)["contained"].pop(r["agent"], None)
        return out
    return eng.agents.register([{**r["spec"], "demo": True}])[0]


def decide(eng, box: str, r: dict, approve: bool, by: str, comment: str, now: float) -> dict | None:
    r.update(status="approved" if approve else "rejected", decided_by=by, decided_at=now, comment=comment)
    return apply(eng, box, r) if approve else None


def _pending_for(st, agent_id: str) -> bool:
    return any(r["status"] == "pending" and r.get("agent") == agent_id for r in st["resp"].values())


def sync(eng, now: float) -> dict:
    """-> {"response_requests": [...], "agent_requests": [...]} newest first, private fields removed."""
    if not getattr(eng, "simulate", False):
        return {"response_requests": [], "agent_requests": []}
    st, rng = _state(eng), _state(eng)["rng"]
    agents = eng.agents.agents
    # 1. contain requests from fresh high/critical AI-agent alerts
    for e in list(eng.events):
        if (e["id"] in st["alerts"] or not str(e.get("rule") or "").startswith("AGT") or e.get("severity") not in ("high", "critical")
                or e.get("simulated") is False or now - e["ts"] > 1800):
            continue
        st["alerts"].add(e["id"])
        aid = e.get("agent")
        if aid in agents and not agents[aid].get("contained") and not _pending_for(st, aid):
            _new(st, "resp", {"action": "contain", "agent": aid, "alert_id": e["id"],
                              "reason": f"{e['title'] if str(e['title']).startswith('[') else e['rule'] + ' ' + e['title']} บน {e.get('host') or '-'} — ขอตัด token ระหว่างสอบสวน"},
                 min(now, e["ts"] + rng.uniform(30, 180)))
    # 2. release requests for agents the demo team contained a while ago
    for aid, t in list(st["contained"].items()):
        ag = agents.get(aid)
        if ag and ag.get("contained") and t and now - t > 20 * 60 and not _pending_for(st, aid):
            _new(st, "resp", {"action": "release", "agent": aid,
                              "reason": "หมุน token แล้ว ตรวจ session ย้อนหลังไม่พบการรั่วไหล — ขอคืนการใช้งาน"}, now)
    # 3. agent-permission requests every 8–20 minutes (two at start so the column is never empty)
    if st["next_ag"] == 0.0:
        st["next_ag"] = now - 1
        _agent_request(eng, st, rng, now - rng.uniform(3, 12) * 60)
    if now >= st["next_ag"]:
        _agent_request(eng, st, rng, now)
        st["next_ag"] = now + rng.uniform(8, 20) * 60
    # 4. lead.demo decides what nobody else did
    for box in ("resp", "ag"):
        for r in st[box].values():
            if r["status"] == "pending" and now >= r["_auto_at"]:
                risky = box == "ag" and r["spec"].get("shell")
                ok = rng.random() < (0.15 if risky else 0.85 if box == "resp" else 0.7)
                note = ("shell ต้องผ่าน security review ก่อน" if risky and not ok else
                        "อนุมัติตามหลักฐานใน alert" if ok else "ข้อมูลยังไม่พอ ขอหลักฐานเพิ่ม")
                decide(eng, box, r, ok, LEAD, note, r["_auto_at"])
        if len(st[box]) > CAP:  # drop the oldest decided first
            for r in sorted(st[box].values(), key=lambda x: (x["status"] == "pending", x["requested_at"]))[:len(st[box]) - CAP]:
                del st[box][r["id"]]
    pub = lambda box: [{k: v for k, v in r.items() if not k.startswith("_")}  # noqa: E731
                       for r in sorted(st[box].values(), key=lambda x: -x["requested_at"])]
    return {"response_requests": pub("resp"), "agent_requests": pub("ag")}


def _agent_request(eng, st, rng, at: float) -> None:
    agents = [a for a in eng.agents.agents.values() if a.get("registered") and a.get("demo")]
    new = [a for a in NEW_AGENTS if a["id"] not in eng.agents.agents
           and not any(r["spec"]["id"] == a["id"] and r["status"] == "pending" for r in st["ag"].values())]
    if new and (not agents or rng.random() < 0.3):
        spec = dict(rng.choice(new))
        _new(st, "ag", {"spec": spec, "change": "new", "reason": f"ลงทะเบียน agent ใหม่ของทีม {spec['owner']}"}, at)
        return
    if not agents:
        return
    a = rng.choice(agents)
    spec = {k: (list(a[k]) if isinstance(a.get(k), list) else a.get(k)) for k in ("id", "owner", "host", "account", "scopes", "egress", "shell")}
    spec["scopes"], spec["egress"] = spec["scopes"] or [], spec["egress"] or []
    kind = rng.choices(["scope", "egress", "shell"], [5, 3, 1])[0]
    if kind == "scope":
        extra = [s for s in EXTRA_SCOPES if s not in spec["scopes"]]
        if not extra:
            return
        add = rng.choice(extra)
        spec["scopes"].append(add)
        why = f"เพิ่ม scope {add} ให้ {a['id']} ตามคำขอของเจ้าของ ({a.get('owner') or '-'})"
    elif kind == "egress":
        extra = [d for d in EXTRA_EGRESS if d not in spec["egress"]]
        if not extra:
            return
        add = rng.choice(extra)
        spec["egress"].append(add)
        why = f"เปิด egress ไป {add} สำหรับ integration ใหม่"
    else:
        if spec["shell"]:
            return
        spec["shell"] = True
        why = f"ขอเปิด shell ให้ {a['id']} เพื่อรันสคริปต์อัตโนมัติ (ความเสี่ยงสูง)"
    _new(st, "ag", {"spec": spec, "change": "update", "reason": why}, at)
