# OSINT Toolkit (MVP)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/lucipherzsatansatanial/osint-toolkit)

Web application สำหรับรวบรวมข้อมูลจากแหล่งเปิด (OSINT) — FastAPI + หน้าเว็บ static (ไม่ต้อง build)

## โมดูล

| โมดูล | ตรวจอะไร | แหล่งข้อมูล | ต้องใช้ key |
|---|---|---|---|
| Domain | DNS (A/AAAA/MX/NS/TXT/SOA/CAA), WHOIS ผ่าน RDAP, subdomains จาก Certificate Transparency, HTTP security headers (เกรด A–F), tech stack, TLS cert | DNS, rdap.org, crt.sh, เว็บเป้าหมาย | ไม่ |
| IP | Reverse DNS, เจ้าของเครือข่าย/CIDR, Geolocation+ASN | DNS, rdap.org, ipinfo.io | Geo: `IPINFO_TOKEN` |
| Email* | SPF / DMARC / DKIM (ประเมินความเสี่ยง spoofing), Gravatar, Data breach | DNS, gravatar.com, HIBP | Breach: `HIBP_API_KEY` |
| Brand | Lookalike/typosquatting domain ที่จดทะเบียนแล้ว (สูงสุด 400 รูปแบบ, มี MX = เสี่ยงสูง), ใบรับรอง SSL ที่มีชื่อแบรนด์ | DNS, crt.sh | ไม่ |
| Username* | ตรวจ handle บน 14 แพลตฟอร์ม (GitHub, Reddit, Telegram ฯลฯ) | API/หน้าสาธารณะ | ไม่ |

\* โมดูลข้อมูลส่วนบุคคล — ระบบบังคับให้เลือก **ฐานทางกฎหมายตาม PDPA** ก่อนสแกน

## SOC Dashboard — EDR / XDR / CTI (`/soc`)

หน้า dashboard แบบ real-time (Server-Sent Events, อัปเดตทุก 1 วินาที) สำหรับ SOC wallboard

| ส่วน | แสดงอะไร | ข้อมูล |
|---|---|---|
| KPI | Events/นาที, open incidents, coordinated attacks, CTI matches, สถานะ endpoint, critical/high | จำลอง |
| Throughput | กราฟเส้นจำนวน event แยกตาม domain (endpoint/identity/email/network/cloud) ย้อนหลัง 5 นาที | จำลอง |
| EDR | รายการ endpoint: healthy / at risk / compromised, Real-time protection, จำนวน alert | จำลอง |
| XDR | Incident ที่ correlate ข้าม domain (entity เดียวกัน user/host ภายใน 30 นาที) + กราฟเชื่อมโยง + timeline | จำลอง + logic จริง |
| MITRE ATT&CK | จำนวน alert ตาม tactic | จำลอง |
| CTI | CISA KEV (CVE ที่ถูกใช้โจมตีจริง), abuse.ch Feodo Tracker (botnet C2), abuse.ch ThreatFox (IOC) | **ข้อมูลจริง** (cache 15 นาที) |

- **Telemetry เป็นข้อมูลจำลอง** (ทุก event มี `"simulated": true` และหน้าเว็บแสดงป้าย SIMULATED) — ใช้สาธิต correlation จนกว่าจะต่อ connector ของ EDR/XDR จริง (เช่น Microsoft Defender XDR, CrowdStrike Falcon, SentinelOne) เข้ากับ `app/telemetry.py`
- Simulator สร้าง noise + kill chain หลายขั้น (phishing → sign-in ผิดปกติ → MFA fatigue → PowerShell → C2 → LSASS dump → lateral movement → exfil/ransomware) เมื่อดึง CTI ได้ event C2/exploit จะอ้างอิง IP ของ Feodo และ CVE ของ KEV จริง และติดธง **CTI match**
- Incident ที่มี ≥2 domain และมี alert ระดับ high ขึ้นไป = **Coordinated attack** และถูกยกระดับความรุนแรง 1 ขั้น
- ThreatFox export อาจต้องใช้ Auth-Key ในอนาคต — ถ้าดึงไม่ได้ dashboard ยังทำงานต่อและแสดง error เฉพาะ feed นั้น

API: `GET /api/soc/snapshot`, `GET /api/soc/cti?refresh=true`, `GET /api/soc/stream` (SSE; ส่ง `X-API-Key` ผ่าน header — หน้าเว็บใช้ `fetch` แทน `EventSource` เพื่อไม่ให้ key ไปอยู่ใน URL)

## การควบคุม (Governance)
- **Audit log** (SQLite): ทุกการสแกนบันทึก analyst, IP, เป้าหมาย, วัตถุประสงค์, legal basis, case ref และผลลัพธ์ — ลบอัตโนมัติตาม `OSINT_RETENTION_DAYS` (ค่าเริ่มต้น 90 วัน)
- **SSRF guard**: ปฏิเสธการเชื่อมต่อไป IP ภายใน/private/metadata (169.254.169.254) และตรวจซ้ำทุก redirect
- **API key** (`OSINT_API_KEY`) + rate limit ต่อ IP
- ผลลัพธ์ Username เป็น *possible match* เท่านั้น — ต้องยืนยันด้วยคน

## รัน

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp .env.example .env   # แก้ค่า แล้ว export หรือใช้ --env-file
.venv/bin/uvicorn app.main:app --port 8000
```
เปิด http://localhost:8000

Docker:
```bash
docker build -t osint-toolkit .
docker run -p 8000:8000 --env-file .env -v osint-data:/app/data osint-toolkit
```

ทดสอบ: `.venv/bin/pytest -q` (49 tests, mock network ทั้งหมด)

## ข้อจำกัดที่ทราบ
- `.th` ไม่มี RDAP → ระบบแจ้งให้ใช้ THNIC WHOIS (ยังไม่ได้ integrate)
- Username checker อาจคลาดเคลื่อนเมื่อแพลตฟอร์มเปลี่ยนหน้าเว็บ หรือบล็อกด้วย 403/429 (แสดงเป็น `unknown`)
- Rate limit อยู่ใน memory (รีเซ็ตเมื่อรีสตาร์ต, ไม่แชร์ข้าม instance)
- SSRF guard ไม่กัน DNS rebinding 100% — production ควรบล็อก private range ที่ egress firewall ด้วย
- ยังไม่มีระบบผู้ใช้/RBAC (ใช้ API key ร่วม)
