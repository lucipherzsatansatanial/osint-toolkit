"""Incident report (self-contained printable HTML) and CSV export. All values are HTML/CSV-escaped."""
import csv
import io
from datetime import datetime, timezone
from html import escape

STATUS_TH = {"open": "เปิด", "investigating": "กำลังสอบสวน", "resolved": "แก้ไขแล้ว",
             "false_positive": "แจ้งเตือนผิด (false positive)", "closed": "ปิดอัตโนมัติ (ไม่มีความเคลื่อนไหว)"}
SEV_COLOR = {"critical": "#c62828", "high": "#d9480f", "medium": "#9a6700", "low": "#1a7f37", "info": "#5d6673"}


def _t(ts) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _e(v) -> str:
    return escape("" if v is None else str(v))


def html_report(inc: dict, generated_by: str = "") -> str:
    alerts = sorted(inc.get("alerts", []), key=lambda a: a.get("ts") or 0)
    techniques = sorted({(a.get("technique") or "", a.get("rule") or "") for a in alerts})
    agents = sorted({a["agent"] for a in alerts if a.get("agent")})
    frameworks = sorted({a["framework"] for a in alerts if a.get("framework")})
    real = inc.get("real", False)
    rows = "".join(
        f"<tr><td>{_t(a.get('ts'))}</td><td><b style='color:{SEV_COLOR.get(a.get('severity'), '#333')}'>"
        f"{_e(a.get('severity'))}</b></td><td>{_e(a.get('domain'))}</td><td>{_e(a.get('title'))}"
        f"{'<div class=s>' + _e(a.get('record')) + '</div>' if a.get('record') else ''}</td>"
        f"<td>{_e(a.get('host'))}<div class=s>{_e(a.get('user'))}</div></td><td>{_e(a.get('technique'))}</td>"
        f"<td>{_e(a.get('cti_match') or '')}{'<div class=s>' + _e(a.get('indicator')) + '</div>' if a.get('indicator') else ''}</td></tr>"
        for a in alerts)
    notes = "".join(f"<li><b>{_e(n.get('analyst'))}</b> · {_t(n.get('ts'))}<div>{_e(n.get('text'))}</div></li>"
                    for n in inc.get("notes", [])) or "<li class=s>ไม่มีบันทึก</li>"
    hist = "".join(f"<li>{_t(h.get('ts'))} · {_e(h.get('analyst'))} · {_e(h.get('change'))}</li>"
                   for h in inc.get("history", [])) or "<li class=s>ไม่มี</li>"
    banner = ("" if real else "<p class=warn>รายงานนี้สร้างจาก<b>ข้อมูลจำลอง</b> (demo) — ห้ามใช้เป็นหลักฐานหรือส่งลูกค้าในฐานะเหตุการณ์จริง</p>")
    return f"""<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident #{_e(inc.get('id'))} report</title>
<style>
body{{font:13px/1.55 "Sarabun","Noto Sans Thai",system-ui,sans-serif;color:#1b1f24;max-width:1000px;margin:24px auto;padding:0 16px;background:#fff}}
h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:15px;margin:22px 0 8px;border-bottom:1px solid #e2e5ea;padding-bottom:4px}}
table{{width:100%;border-collapse:collapse;font-size:12px}} th,td{{text-align:left;border-bottom:1px solid #eef1f5;padding:5px 6px;vertical-align:top}}
th{{color:#5d6673;font-weight:600}} .s{{color:#5d6673;font-size:11px;word-break:break-all}} .kv td:first-child{{width:200px;color:#5d6673}}
.warn{{background:#fff4e5;border:1px solid #f0c36d;padding:8px 10px;border-radius:6px}}
ul{{padding-left:18px}} .foot{{margin-top:28px;color:#5d6673;font-size:11px}}
@media print{{body{{margin:0}} .noprint{{display:none}}}}
</style></head><body>
<p class="noprint"><button onclick="window.print()">พิมพ์ / บันทึกเป็น PDF</button></p>
<h1>Incident #{_e(inc.get('id'))} — {_e(inc.get('title'))}</h1>
<div class=s>สร้างรายงาน {_t(datetime.now(tz=timezone.utc).timestamp())}{' โดย ' + _e(generated_by) if generated_by else ''}</div>
{banner}
<h2>สรุป</h2>
<table class=kv>
<tr><td>ความรุนแรง</td><td><b style="color:{SEV_COLOR.get(inc.get('severity'), '#333')}">{_e(inc.get('severity'))}</b>{' · การโจมตีหลายโดเมน (coordinated)' if inc.get('coordinated') else ''}</td></tr>
<tr><td>สถานะ</td><td>{_e(STATUS_TH.get(inc.get('status'), inc.get('status')))}</td></tr>
<tr><td>ผู้รับผิดชอบ</td><td>{_e(inc.get('assignee') or '-')}</td></tr>
<tr><td>ช่วงเวลา</td><td>{_t(inc.get('first_ts'))} → {_t(inc.get('last_ts'))}</td></tr>
<tr><td>แหล่งข้อมูล</td><td>{'log จริงที่นำเข้าระบบ' if real else 'ข้อมูลจำลอง'} · {len(alerts)} alerts · โดเมน: {_e(', '.join(inc.get('domains', [])))}</td></tr>
<tr><td>เครื่องที่เกี่ยวข้อง</td><td>{_e(', '.join(inc.get('hosts', [])))}</td></tr>
<tr><td>ผู้ใช้ / บัญชี</td><td>{_e(', '.join(inc.get('users', [])))}</td></tr>
{'<tr><td>AI agents</td><td>' + _e(', '.join(agents)) + '</td></tr>' if agents else ''}
{'<tr><td>Offensive-AI framework</td><td>' + _e(', '.join(frameworks)) + '</td></tr>' if frameworks else ''}
<tr><td>MITRE ATT&amp;CK / ATLAS</td><td>{_e(', '.join(t for t, _ in techniques if t))}</td></tr>
<tr><td>Tactics</td><td>{_e(' → '.join(inc.get('tactics', [])))}</td></tr>
</table>
<h2>Timeline ของ alert</h2>
<table><tr><th>เวลา</th><th>ระดับ</th><th>โดเมน</th><th>เหตุการณ์ / หลักฐาน</th><th>Host / ผู้ใช้</th><th>Technique</th><th>CTI</th></tr>{rows}</table>
<h2>บันทึกของ analyst</h2><ul>{notes}</ul>
<h2>ประวัติการเปลี่ยนแปลง</h2><ul>{hist}</ul>
<p class=foot>ผลจาก detection rule เป็นสัญญาณให้ตรวจสอบ ไม่ใช่ข้อสรุป ต้องยืนยันด้วยหลักฐานจากระบบต้นทางก่อนสรุปผลหรือดำเนินการทางกฎหมาย ·
Mapping ATT&amp;CK/ATLAS เป็นแนวทาง · เวลาแสดงเป็น UTC</p>
</body></html>"""


CSV_FIELDS = ["id", "title", "severity", "status", "assignee", "real", "coordinated", "first_seen_utc", "last_seen_utc",
              "alerts", "domains", "hosts", "users", "techniques", "rules", "notes"]


def _cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # block spreadsheet formula injection


def csv_export(incidents: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    for i in incidents:
        al = i.get("alerts", [])
        w.writerow([_cell(x) for x in (
            i.get("id"), i.get("title"), i.get("severity"), i.get("status"), i.get("assignee") or "",
            i.get("real", False), i.get("coordinated", False), _t(i.get("first_ts")), _t(i.get("last_ts")), len(al),
            "; ".join(i.get("domains", [])), "; ".join(i.get("hosts", [])), "; ".join(i.get("users", [])),
            "; ".join(sorted({a.get("technique") or "" for a in al} - {""})),
            "; ".join(sorted({a.get("rule") or "" for a in al} - {""})), len(i.get("notes", [])))])
    return "﻿" + buf.getvalue()  # BOM so Excel opens Thai text correctly
