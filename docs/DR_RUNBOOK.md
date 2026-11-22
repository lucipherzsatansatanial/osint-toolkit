# HA / DR runbook (SOC Threat Monitor)

## สถาปัตยกรรมปัจจุบัน (ข้อเท็จจริง)
- โปรเซสเดียว (FastAPI + engine ในหน่วยความจำต่อ tenant) + SQLite ไฟล์เดียว (`OSINT_DB_PATH`)
- สิ่งที่เก็บถาวร: alert/incident/agent record/agent/endpoint/custom rule (แยก tenant), ผู้ใช้, audit log (hash chain)
- สิ่งที่**ไม่**เก็บถาวร: sliding window ของกฎ, raw record buffer 5,000 รายการ, CTI cache (โหลดใหม่เองหลังเริ่มระบบ)
- **ยังไม่มี HA**: รันได้ instance เดียว เพราะ engine อยู่ในหน่วยความจำและ SQLite ไม่รองรับหลายเครื่องเขียนพร้อมกัน

## Health check
| Endpoint | ใช้ทำอะไร |
|---|---|
| `GET /healthz` | liveness — process ยังทำงาน (ใช้เป็น health check ของ Render) |
| `GET /readyz` | readiness — DB เขียนได้, engine ของ tenant default โหลดแล้ว, ticker ทำงาน (503 ถ้าไม่พร้อม) |

## Backup
- **อัตโนมัติ**: ตั้ง `SOC_BACKUP_DIR` (โฟลเดอร์บน persistent disk หรือโฟลเดอร์ที่ sync ไป object storage), `SOC_BACKUP_HOURS` (ค่าเริ่มต้น 24), `SOC_BACKUP_KEEP` (7) — ใช้ SQLite backup API จึงได้สำเนาที่สอดคล้องกันขณะระบบทำงาน
- **ด้วยมือ**: platform admin กด "ดาวน์โหลด backup" ในการ์ด Governance หรือ `GET /api/admin/backup` (บันทึกใน audit log)
- ไฟล์ backup มีข้อมูลทุก tenant และข้อมูลส่วนบุคคล → เก็บแบบเข้ารหัส จำกัดผู้เข้าถึง และกำหนดระยะเก็บตามนโยบาย PDPA

## Restore (RTO เป้าหมาย ~30–60 นาที สำหรับ single instance)
1. หยุด service (หรือ scale เป็น 0)
2. วางไฟล์ backup ล่าสุดเป็น `OSINT_DB_PATH` (เช่น `/var/data/osint.db`)
3. เริ่ม service → ตรวจ `GET /readyz` = 200
4. เข้า `/soc` ด้วย platform admin → การ์ด Governance → **ตรวจความครบถ้วน (hash chain)** ต้องได้ ✓
5. ตรวจว่า incident/ผู้ใช้/กฎที่สร้างเองกลับมาครบ แล้วบันทึกเหตุการณ์ใน incident log ของทีม
- RPO = ระยะห่างระหว่าง backup (ค่าเริ่มต้น 24 ชม.) — ลดได้ด้วย `SOC_BACKUP_HOURS=1`

## ตัวเลือกโครงสร้างพื้นฐาน (ต้องตัดสินใจ)
ราคาเป็นข้อมูลประกอบที่ยังไม่ได้ยืนยันกับหน้าราคาจริง — ตรวจที่ https://render.com/pricing ก่อนตัดสินใจ

| ตัวเลือก | เหมาะกับ | HA | RPO / RTO | งานพัฒนาเพิ่ม |
|---|---|---|---|---|
| **A. Render แผนเสียเงิน 1 instance + persistent disk (SQLite)** | นำร่อง / ลูกค้า 1–3 ราย | ไม่มี (disk ผูกกับ instance เดียว) | 1–24 ชม. / 30–60 นาที | ไม่มี — ตั้งค่าเท่านั้น |
| **B. หลาย instance + Postgres ที่มี HA + shared state** | บริการ MSSP หลายลูกค้า | มี | นาที / นาที | มาก: ย้าย SQLite→Postgres, ย้าย engine state ออกจากหน่วยความจำ (เช่น Redis/queue), leader election สำหรับ ticker |
| **C. โฮสต์ในประเทศไทย / on-prem ลูกค้า** | ลูกค้าภาครัฐ/การเงินที่ต้องการให้ข้อมูลอยู่ในไทย | ขึ้นกับโครงสร้าง | ตามที่ออกแบบ | ปานกลาง: Docker image พร้อมแล้ว |

ข้อมูลประกอบ (จากการค้นหา ยังไม่ยืนยัน): persistent disk ~$0.25/GB-เดือน, Render Postgres storage ~$0.30/GB-เดือน, Postgres compute แยกจาก storage (ราคาแต่ละระดับแหล่งข้อมูลไม่ตรงกัน)

## ข้อแนะนำ
1. **ตอนนี้ (นำร่อง)**: ตัวเลือก A — เปลี่ยนจาก free เป็นแผนเสียเงิน, เพิ่ม disk เล็ก (เช่น 1–5 GB), ตั้ง `OSINT_DB_PATH=/var/data/osint.db`, `SOC_BACKUP_DIR=/var/data/backups`, และดาวน์โหลด backup ออกนอกระบบสัปดาห์ละครั้ง
2. **ก่อนรับลูกค้ารายที่ 4+ หรือมี SLA**: วางแผนตัวเลือก B เป็นโครงการแยก
3. **ลูกค้าที่ข้อมูลต้องอยู่ในไทย**: ตัวเลือก C
