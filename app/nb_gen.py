"""Generate investigation notebooks from what the platform already knows — no AI, no invented facts.

- case_report: one case → summary, timeline, hosts / accounts / indicators, CTI matches, response-plan checklist,
  linked tasks, then empty "findings / next steps" sections for the analyst to fill in.
- handover: a shift hand-over note for the SOC manager → alert volume, new and still-open serious cases, unassigned
  work, overdue / blocked tasks, pending approvals, most-hit hosts and most-fired rules in the last N hours.

Output uses the notebook's Markdown subset (headings, lists, bold, code) so it renders in the UI as is.
"""
import time
from collections import Counter

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
TASK_TH = {"pending": "รอดำเนินการ", "awaiting_input": "รอข้อมูล", "in_progress": "กำลังทำ", "completed": "เสร็จแล้ว",
           "cancelled": "ยกเลิก"}
PHASE_TH = {"contain": "กักกัน", "eradicate": "กำจัด", "recover": "กู้คืน", "notify": "แจ้ง", "lessons": "บทเรียน"}


def _t(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


def _c(v) -> str:  # inline code that cannot break out of the backticks
    return "`" + str(v).replace("`", "'")[:120] + "`"


def case_report(inc: dict, plan: dict | None, tasks: list[dict], now: float) -> tuple[str, str]:
    alerts = sorted(inc.get("alerts", []), key=lambda a: a.get("ts") or 0)
    title = f"รายงานการสืบสวน INC-{inc['id']} · {str(inc.get('title') or inc.get('name') or '')[:80]}"
    L = [f"# INC-{inc['id']} — {inc.get('title') or inc.get('name') or ''}", "",
         f"*สร้างอัตโนมัติจากข้อมูลในระบบเมื่อ {_t(now)} — ตรวจและเติมส่วน \"สิ่งที่พบ\" ก่อนใช้เป็นรายงาน*", "",
         "## สรุป",
         f"- **ความรุนแรง:** {inc.get('severity', '-')} · **สถานะ:** {inc.get('status', '-')} · **Priority:** {inc.get('priority') or '-'}",
         f"- **ผู้รับผิดชอบ:** {inc.get('assignee') or 'ยังไม่มอบหมาย'} · **Verdict:** {inc.get('verdict') or 'ยังไม่สรุป'}",
         f"- **ช่วงเวลา:** {_t(inc.get('first_ts'))} → {_t(inc.get('last_ts'))} · **จำนวน alert:** {len(alerts)}",
         f"- **โดเมน:** {', '.join(inc.get('domains') or []) or '-'} · **Tactics:** {', '.join(inc.get('tactics') or []) or '-'}"]
    if inc.get("coordinated"):
        L.append("- **Coordinated attack:** ครอบคลุมหลายโดเมน (ระบบยกความรุนแรง 1 ขั้น)")
    hosts = list(dict.fromkeys(inc.get("hosts") or [a.get("host") for a in alerts if a.get("host")]))
    users = [u for u in dict.fromkeys(inc.get("users") or [a.get("user") for a in alerts]) if u and u not in ("unknown", "system", "-")]
    iocs = list(dict.fromkeys(str(a.get("indicator") or a.get("remote_ip")) for a in alerts if a.get("indicator") or a.get("remote_ip")))
    L += ["", "## สิ่งที่เกี่ยวข้อง",
          f"- **เครื่อง:** {', '.join(_c(h) for h in hosts[:15]) or '-'}",
          f"- **บัญชี:** {', '.join(_c(u) for u in users[:15]) or '-'}",
          f"- **Indicators:** {', '.join(_c(i) for i in iocs[:15]) or '-'}"]
    cti = Counter(a.get("cti_match") for a in alerts if a.get("cti_match"))
    if cti:
        L += ["", "## ตรงกับ Threat Intelligence"] + [f"- {k} — {n} alert" for k, n in cti.most_common(8)]
    L += ["", "## Timeline (alert)"]
    for a in alerts[-25:]:
        L.append(f"- {_t(a.get('ts'))} · **{a.get('severity')}** · {a.get('title')} · {_c(a.get('host') or '-')}"
                 + (f" · {a.get('technique')}" if a.get("technique") else "") + (f" · rule {a.get('rule')}" if a.get("rule") else ""))
    if len(alerts) > 25:
        L.append(f"- … และอีก {len(alerts) - 25} alert ก่อนหน้า (ดูแท็บ Alerts ของ case)")
    if plan:
        L += ["", f"## แผนตอบสนอง ({round(100 * plan.get('progress', 0))}% เสร็จ)"]
        for s in plan.get("steps", []):
            L.append(f"- {'✅' if s.get('done') else '⬜'} [{PHASE_TH.get(s['phase'], s['phase'])}] {s['action']} — {s['owner']}"
                     + (f" (โดย {s['done_by']})" if s.get("done") and s.get("done_by") else ""))
    mine = [t for t in tasks if t.get("incident_id") == inc["id"]]
    if mine:
        L += ["", "## งานที่เกี่ยวข้อง"] + [f"- {TASK_TH.get(t['status'], t['status'])} · {t['name']} · {t.get('assignee') or 'ยังไม่มอบหมาย'}"
                                           + (f" · กำหนดส่ง {_t(t['due'])}" if t.get("due") else "") for t in mine]
    L += ["", "## สิ่งที่พบ (analyst เติม)", "- ", "", "## ขั้นตอนต่อไป", "1. "]
    return title, "\n".join(L)


def handover(events: list[dict], incidents: list[dict], tasks: list[dict], pending_approvals: int, now: float,
             hours: int = 12, tenant: str = "") -> tuple[str, str]:
    start = now - hours * 3600
    win = [e for e in events if (e.get("ts") or 0) >= start]
    sev = Counter(e.get("severity") for e in win)
    new_inc = [i for i in incidents if (i.get("first_ts") or 0) >= start]
    open_bad = sorted((i for i in incidents if i.get("status") in ("open", "investigating") and i.get("severity") in ("critical", "high")),
                      key=lambda i: (SEV_ORDER.get(i.get("severity"), 9), -(i.get("last_ts") or 0)))
    unassigned = [i for i in open_bad if not i.get("assignee")]
    live = [t for t in tasks if t.get("status") not in ("completed", "cancelled")]
    overdue = [t for t in live if t.get("due") and t["due"] < now]
    blocked = [t for t in live if t.get("status") == "awaiting_input"]
    title = f"ส่งเวร SOC {time.strftime('%Y-%m-%d %H:%M', time.localtime(now))} ({hours} ชม.)"
    L = [f"# บันทึกส่งเวร — {hours} ชั่วโมงที่ผ่านมา", "",
         f"*สร้างอัตโนมัติเมื่อ {_t(now)}{' · tenant ' + tenant if tenant else ''} — ผู้ส่งเวรตรวจ เติมหมายเหตุ แล้วบันทึก*", "",
         "## ภาพรวม",
         f"- **Alerts:** {len(win):,} (critical {sev.get('critical', 0)} · high {sev.get('high', 0)} · medium {sev.get('medium', 0)} · low {sev.get('low', 0)})",
         f"- **Case ใหม่:** {len(new_inc)} · **case critical/high ที่ยังเปิด:** {len(open_bad)} (ยังไม่มีผู้รับผิดชอบ {len(unassigned)})",
         f"- **งานค้าง:** {len(live)} (เลยกำหนด {len(overdue)} · รอข้อมูล {len(blocked)}) · **คำขอรออนุมัติ:** {pending_approvals}",
         "", "## Case ที่ต้องตามต่อ"]
    L += [f"- **INC-{i['id']}** {i.get('severity')} · {str(i.get('title') or i.get('name') or '')[:90]} · {i.get('status')} · "
          f"{i.get('assignee') or '**ยังไม่มอบหมาย**'} · ล่าสุด {_t(i.get('last_ts'))}" for i in open_bad[:12]] or ["- ไม่มี"]
    if len(open_bad) > 12:
        L.append(f"- … และอีก {len(open_bad) - 12} case")
    L += ["", "## งานที่ติดหรือเลยกำหนด"]
    L += [f"- {TASK_TH.get(t['status'], t['status'])} · {t['name'][:100]} · {t.get('assignee') or 'ยังไม่มอบหมาย'}"
          + (f" · INC-{t['incident_id']}" if t.get("incident_id") else "") + (" · **เลยกำหนด**" if t in overdue else "")
          for t in (overdue + [b for b in blocked if b not in overdue])[:12]] or ["- ไม่มี"]
    hosts = Counter(e.get("host") for e in win if e.get("host") and e.get("severity") in ("critical", "high"))
    rules = Counter(e.get("rule") or e.get("title") for e in win if e.get("severity") != "info")
    L += ["", "## เครื่องที่มี alert ระดับ high/critical มากที่สุด"] + ([f"- {_c(h)} — {n}" for h, n in hosts.most_common(5)] or ["- ไม่มี"])
    L += ["", "## Rule / alert ที่เกิดบ่อย"] + ([f"- {r} — {n}" for r, n in rules.most_common(5)] or ["- ไม่มี"])
    L += ["", "## หมายเหตุผู้ส่งเวร", "- ", "", "## สิ่งที่เวรถัดไปต้องทำก่อน", "1. "]
    return title, "\n".join(L)
