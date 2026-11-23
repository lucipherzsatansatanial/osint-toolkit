"""Demo tasks for the simulated (demo) tenant.

The simulator creates incidents but nobody works them, so the Tasks board stays empty. This module plays a small
demo SOC team: for every simulated high/critical incident it opens tasks from that incident's own response plan
(app.phase4.response_plan) and moves them along over time (pending → in progress → done, some waiting for input,
some cancelled when the incident goes quiet).

Rules that keep demo data honest:
- only engines with the simulator on, and only incidents built from simulated alerts;
- kept in memory on the engine (never written to the database) with negative ids, `simulated: True`, and a
  "(จำลอง)" creator — the UI marks them and the API refuses to edit them;
- assignees are fictional demo accounts ending in ".demo", never real users.
"""
import random

from app import phase4

TEAM = ["somchai.demo", "nok.demo", "pim.demo", "arthit.demo", "kanya.demo", "lead.demo"]
MAX_PER_INCIDENT = 3
SEVERE = ("high", "critical")


def _rng(key: str) -> random.Random:
    return random.Random(key)  # deterministic per task, so a task's timeline never jumps between refreshes


def _new_tasks(eng, inc: dict, now: float) -> list[dict]:
    plan = phase4.response_plan(inc)
    out = []
    for step in plan["steps"][:MAX_PER_INCIDENT]:
        eng._demo_task_seq -= 1
        tid = eng._demo_task_seq
        r = _rng(f"{eng.tenant}:{inc['id']}:{step['id']}")
        created = max(inc.get("first_ts") or now, now - 6 * 3600)
        due_h = {"contain": r.uniform(0.5, 4), "eradicate": r.uniform(4, 24), "recover": r.uniform(12, 72)}.get(step["phase"], 24)
        out.append({
            "id": tid, "name": step["action"][:200], "simulated": True,
            "description": f"{step['phase']} · ผู้รับผิดชอบตามแผน: {step['owner']} · จากแผนตอบสนองของ INC-{inc['id']}",
            "assignee": r.choice(TEAM) if r.random() < 0.85 else None, "status": "pending",
            "due": created + due_h * 3600, "incident_id": inc["id"], "created_by": "SOC Lead (จำลอง)",
            "created_at": created, "updated_at": created, "notes": [],
            "history": [{"ts": created, "analyst": "SOC Lead (จำลอง)", "change": "สร้างจากแผนตอบสนอง (ข้อมูลจำลอง)"}],
            # private timeline of the demo
            "_start": created + r.uniform(0.5, 6) * 60, "_done": created + r.uniform(8, 90) * 60,
            "_wait": r.random() < 0.15, "_phase": step["phase"]})
    return out


def _advance(t: dict, inc: dict | None, now: float) -> None:
    def move(status, ts, note):
        if t["status"] == status:
            return
        t["history"].append({"ts": ts, "analyst": t.get("assignee") or "SOC Lead (จำลอง)", "change": f"status {t['status']} → {status}" + (f" · {note}" if note else "")})
        t["status"], t["updated_at"] = status, ts
        if status == "completed":
            t["completed_at"] = ts
    if t["status"] in ("completed", "cancelled"):
        return
    closed = inc is not None and inc.get("status") in ("closed", "resolved", "false_positive")
    if closed and t["status"] == "pending":
        move("cancelled", now, "incident ปิดแล้ว")
        return
    if t["assignee"] is None and now >= t["_start"]:
        t["assignee"] = _rng(str(t["id"])).choice(TEAM)
        t["history"].append({"ts": t["_start"], "analyst": t["assignee"], "change": f"assignee → {t['assignee']}"})
    if now >= t["_start"]:
        move("in_progress", t["_start"], "")
    if t["_wait"] and now >= (t["_start"] + t["_done"]) / 2:
        move("awaiting_input", (t["_start"] + t["_done"]) / 2, "รอข้อมูลจากเจ้าของระบบ")
        return  # waits until someone answers — stays on the board as a realistic blocker
    if now >= t["_done"]:
        move("completed", t["_done"], "")


def sync(eng, now: float) -> list[dict]:
    """Bring the engine's demo tasks up to date and return them (newest first, private fields removed)."""
    if not getattr(eng, "simulate", False):
        return []
    if not hasattr(eng, "demo_tasks"):
        eng.demo_tasks, eng._demo_task_incs, eng._demo_task_seq = {}, set(), 0
    for inc in list(eng.incidents.values()):
        if inc["id"] in eng._demo_task_incs or inc.get("severity") not in SEVERE:
            continue
        if any(a.get("simulated") is False for a in inc.get("alerts", [])):
            continue  # real incident: real people create its tasks
        eng._demo_task_incs.add(inc["id"])
        for t in _new_tasks(eng, inc, now):
            eng.demo_tasks[t["id"]] = t
    for t in eng.demo_tasks.values():
        _advance(t, eng.incidents.get(t["incident_id"]), now)
    cap = 60 * max(1, getattr(eng, "scale", 1))
    if len(eng.demo_tasks) > cap:  # drop the oldest finished tasks first, then the oldest
        order = sorted(eng.demo_tasks.values(), key=lambda t: (t["status"] not in ("completed", "cancelled"), t["created_at"]))
        for t in order[:len(eng.demo_tasks) - cap]:
            del eng.demo_tasks[t["id"]]
    return [{k: v for k, v in t.items() if not k.startswith("_")}
            for t in sorted(eng.demo_tasks.values(), key=lambda t: -t["created_at"])]
