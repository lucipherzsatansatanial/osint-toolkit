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

### Agentic AI Threat Detection & Hunting

ตรวจจับภัยที่มาจาก/ผ่าน AI Agent โดยอ่าน **AI Agent Audit Logs** (prompt provenance, tool invocation, process launch, network connection, การขอสิทธิ์) แล้ว correlate กับ EDR / NDR / identity / email ใน XDR incident เดียวกัน (เชื่อมด้วย host ของ agent และผู้ใช้ที่ agent ทำงานแทน `on_behalf_of`)

| Rule | ตรวจอะไร | Mapping |
|---|---|---|
| AGT-001 | เรียก tool นอก permission scope (policy gateway ปฏิเสธ = denied) | T1078 |
| AGT-002 | Agent ขอเพิ่มสิทธิ์ / role | T1098 |
| AGT-003 | Agent ที่ไม่มีสิทธิ์ shell แต่ spawn shell (process tree) | T1059 |
| AGT-004 | เข้าถึง secrets (.env, id_rsa, vault, api key) | T1552.001 |
| AGT-005 / 006 | Egress ไปปลายทางนอก allowlist / ไป C2 ที่ตรงกับ CTI | T1071.001 |
| AGT-007 | เนื้อหาที่ดึงมา (email/เอกสาร) มีสัญญาณ prompt injection | ATLAS AML.T0051.001 |
| AGT-008 | ทำ action อ่อนไหวหลังเจอ prompt injection ใน session เดียวกัน | ATLAS AML.T0051.001 |
| AGT-009 | อ่านข้อมูลจำนวนมาก แล้วส่งออกนอกองค์กร | T1567 |
| AGT-010 | อัตราการเรียก tool ผิดปกติ (>25 ครั้ง/นาที) | T1119 |

- **Hunting**: ภาษา query แบบ `field:value` เช่น `agent:support kind:tool_call -decision:allowed`, `rule:*`, `kind:process`
- **Session drill-down**: process tree, network connections, execution log ต่อ session
- **Response**: ปุ่ม Contain/Release (จำลองการ revoke token / suspend agent) บังคับใส่ชื่อผู้ปฏิบัติงานและเหตุผล บันทึกลง audit log
- กฎใน `app/agent_detect.py` ใช้กับ log จริงได้ถ้าแปลงให้อยู่ใน record shape เดียวกัน (เช่น จาก agent gateway / MCP proxy, EDR process events, NDR/firewall ผ่าน SIEM) — ตอนนี้ข้อมูล agent เป็น**ข้อมูลจำลอง**
- Mapping ATT&CK/ATLAS เป็นการจับคู่เชิงแนวทาง ควรทบทวนกับเวอร์ชันล่าสุดของ framework ก่อนใช้ในรายงานลูกค้า

API: `GET /api/soc/agents`, `GET /api/soc/agents/sessions/{sid}`, `GET /api/soc/hunt?q=`, `POST /api/soc/agents/{id}/contain`

### Offensive AI Agent Detection (ARTEX/AntiFox, Cairn, PentAGI, HexStrike, CyberStrikeAI, Strix, Hermes Agent, Agent Zero)

ตรวจจับ**ผู้โจมตีที่ใช้ AI Agent** จาก telemetry ของ EDR / NDR / web log (`app/offensive_ai.py`) แบ่ง 2 ชั้น:

| Rule | พฤติกรรม |
|---|---|
| OAI-001 | AI agent CLI ถูกเปิดแบบปิดการขออนุมัติ (`--dangerously-skip-permissions`, `--yolo`, `HERMES_YOLO_MODE` ฯลฯ) แล้วเรียกเครื่องมือโจมตี |
| OAI-002 | เซิร์ฟเวอร์ติดต่อ API โมเดล AI ภายนอก — ผู้ให้บริการจากจีน (DeepSeek, Qwen, GLM, Kimi, MiniMax, Doubao ฯลฯ) ยกเป็น high |
| OAI-003 | เรียกเครื่องมือโจมตีหลายชนิดอย่างรวดเร็วจากแหล่งเดียว (≥4 ชนิด / 2 นาที) |
| OAI-004 | สแกนผ่าน proxy หมุนเวียน (≥20 IP ที่ยิงน้อยครั้งและเกือบทั้งหมด error ใส่เป้าเดียวใน 5 นาที) |
| OAI-005 | ทำงานหลายขั้นต่อเนื่อง recon → scan → exploit → post บน entity เดียวภายใน 15 นาที |
| OAI-006 | ตรง indicator ของ framework (UA, string, ไฟล์, docker image, IP, domain) |
| OAI-007 | Callback ไปบริการ OAST (interactsh, Burp Collaborator, dnslog.cn ฯลฯ) |

- Indicator ดึงสดจาก [ThreatDefence/agentic-attack-detections](https://github.com/ThreatDefence/agentic-attack-detections) (MIT) — ตัดรายการที่เลย `review_by` และไม่ alert รายการ confidence ต่ำ
- Hunting query: `detections/offensive_ai/` — KQL (Defender XDR/Sentinel), SPL (Splunk), Sigma; แสดงและคัดลอก/ดาวน์โหลดได้จากหน้า dashboard — ดูสถานะการทดสอบใน `detections/offensive_ai/README.md`
- API: `GET /api/soc/offensive-ai`

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

ทดสอบ: `.venv/bin/pytest -q` (65 tests, mock network ทั้งหมด)

## ข้อจำกัดที่ทราบ
- `.th` ไม่มี RDAP → ระบบแจ้งให้ใช้ THNIC WHOIS (ยังไม่ได้ integrate)
- Username checker อาจคลาดเคลื่อนเมื่อแพลตฟอร์มเปลี่ยนหน้าเว็บ หรือบล็อกด้วย 403/429 (แสดงเป็น `unknown`)
- Rate limit อยู่ใน memory (รีเซ็ตเมื่อรีสตาร์ต, ไม่แชร์ข้าม instance)
- SSRF guard ไม่กัน DNS rebinding 100% — production ควรบล็อก private range ที่ egress firewall ด้วย
- ยังไม่มีระบบผู้ใช้/RBAC (ใช้ API key ร่วม)
