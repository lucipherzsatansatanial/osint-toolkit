# OSINT Toolkit (MVP)

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

ทดสอบ: `.venv/bin/pytest -q` (44 tests, mock network ทั้งหมด)

## ข้อจำกัดที่ทราบ
- `.th` ไม่มี RDAP → ระบบแจ้งให้ใช้ THNIC WHOIS (ยังไม่ได้ integrate)
- Username checker อาจคลาดเคลื่อนเมื่อแพลตฟอร์มเปลี่ยนหน้าเว็บ หรือบล็อกด้วย 403/429 (แสดงเป็น `unknown`)
- Rate limit อยู่ใน memory (รีเซ็ตเมื่อรีสตาร์ต, ไม่แชร์ข้าม instance)
- SSRF guard ไม่กัน DNS rebinding 100% — production ควรบล็อก private range ที่ egress firewall ด้วย
- ยังไม่มีระบบผู้ใช้/RBAC (ใช้ API key ร่วม)
