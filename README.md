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
| OAI-008 | Web/API recon burst จาก IP เดียว (≥60 req/นาที, error สูงหรือ path หลากหลาย) |
| OAI-009 | Lateral movement fan-out: เครื่อง/บัญชีเดียวเข้าถึง ≥10 เครื่องใน 10 นาที (admin ports หรือ network logon) |
| OAI-010 | การเข้าถึงฐานข้อมูลผิดปกติ: คำสั่ง dump/export หรืออ่านข้อมูลจำนวนมาก |
| OAI-011 | ส่งข้อมูลออกภายนอกหลังการเข้าถึงข้อมูลจำนวนมาก / DLP พบข้อมูลลับออกนอกองค์กร |
| OAI-012 | หลาย AI agent (approvals off) ทำงานพร้อมกันบนเครื่องเดียว — แบบ CAIRN |
| OAI-013 | เครื่องมือโจมตีถูกเรียกโดย MCP server — แบบ HexStrike |
| OAI-014 | Agent สั่ง download-and-execute / reverse shell / โค้ดเข้ารหัส / inline code — แบบ Hermes, Agent Zero |

ตาราง use case + Priority + แหล่ง log: [`detections/USE_CASES.md`](detections/USE_CASES.md) · AGT-012: MCP tool invocation ผิดนโยบาย (allowlist `mcp_servers` ตอนลงทะเบียน agent)

- Indicator ดึงสดจาก [ThreatDefence/agentic-attack-detections](https://github.com/ThreatDefence/agentic-attack-detections) (MIT) — ตัดรายการที่เลย `review_by` และไม่ alert รายการ confidence ต่ำ
- Hunting query: `detections/offensive_ai/` — KQL (Defender XDR/Sentinel), SPL (Splunk), Sigma; แสดงและคัดลอก/ดาวน์โหลดได้จากหน้า dashboard — ดูสถานะการทดสอบใน `detections/offensive_ai/README.md`
- API: `GET /api/soc/offensive-ai`

### ส่ง log จริงเข้า SOC Dashboard (EDR / NDR / SIEM / AI Agent Audit Logs)

```bash
export SOC_API_KEY=<OSINT_API_KEY>
python3 tools/ship_logs.py export.json --format defender --url https://<host>      # Defender XDR advanced hunting export
python3 tools/ship_logs.py winlogbeat.ndjson --format ecs --url https://<host>     # Elastic / Winlogbeat / Packetbeat (ECS)
python3 tools/ship_logs.py access.log --format access_log --host SRV-WEB-01        # Apache/Nginx combined log
python3 tools/ship_logs.py agent_audit.ndjson --url https://<host>                 # AI agent audit log (native schema)
```

| Endpoint | ทำอะไร |
|---|---|
| `POST /api/soc/ingest?format=auto\|native\|ecs\|defender\|access_log` | รับ JSON array, `{"records": [...]}`, NDJSON หรือ access log (≤5 MB, ≤5,000 records ต่อครั้ง) แล้วรันผ่าน detector ทุกตัว + XDR correlation |
| `POST /api/soc/agents/register` | ลงทะเบียน AI agent จริง พร้อม `scopes`, `egress`, `shell` — agent ที่มี log แต่ไม่ได้ลงทะเบียนจะขึ้น **AGT-011 shadow AI** |

- Schema และ mapping อยู่ใน `app/ingest.py`; ตัวอย่างไฟล์ (ข้อมูลสังเคราะห์) อยู่ใน `samples/`
- Event จาก log จริงมีป้าย **REAL** บนหน้าเว็บ และไม่มีการเติมข้อมูลสมมุติ (เช่น ประเทศต้นทาง)
- Replay log เก่า: เวลาเหตุการณ์ใช้ timestamp ใน log; KPI "ต่อนาที" นับตามเวลาปัจจุบัน
- ปุ่ม Contain ในโหมดจริง **บันทึกสถานะและ audit log เท่านั้น** ยังไม่ได้สั่ง revoke token ที่ระบบปลายทาง

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `SOC_SIMULATION` | `on` | `off` = ใช้เฉพาะ log จริง (ไม่มี demo host/agent/event) |
| `SOC_AI_APPROVED_HOSTS` | `SRV-AI-01,SRV-AI-02` | host ที่อนุญาตให้เรียก API โมเดล AI (OAI-002 จะไม่แจ้ง) |
| `SOC_SERVER_PREFIXES` | `SRV` | prefix ชื่อเครื่องที่ถือเป็น server สำหรับ OAI-002 |

### Incident workflow และการเก็บข้อมูลถาวร

- **เก็บถาวรเฉพาะข้อมูลจริง** (SQLite ไฟล์เดียวกับ audit log): alert, incident, AI-agent audit record, agent ที่ลงทะเบียน, endpoint — restart แล้วโหลดกลับมาครบ; ข้อมูลจำลองไม่ถูกบันทึกและไม่ถูกรวมเข้ากับ incident จริง
- **Workflow**: สถานะ `open → investigating → resolved / false_positive` (incident ที่ไม่มีความเคลื่อนไหว 30 นาทีและยังไม่มีคนรับจะ `closed` อัตโนมัติ), ผู้รับผิดชอบ, บันทึกของ analyst — ทุกการเปลี่ยนแปลงลง audit log
- **รายงาน**: ปุ่ม "รายงาน (HTML/PDF)" ในหน้ารายละเอียด incident (พิมพ์เป็น PDF ได้) และ "Export CSV" (เปิดใน Excel ได้ภาษาไทย, กัน formula injection)
- ข้อจำกัด: state ของกฎแบบ sliding window (fan-out, rotating proxy, multi-stage) เริ่มใหม่หลัง restart
- **Render free plan** เก็บ DB ไว้ที่ `/tmp` ซึ่งหายเมื่อ redeploy/หลับ — ถ้าต้องการเก็บถาวรจริงต้องใช้ persistent disk (แผนเสียเงิน) แล้วตั้ง `OSINT_DB_PATH` ไปที่ disk นั้น

API: `GET /api/soc/incidents`, `GET /api/soc/incidents/{id}`, `PATCH /api/soc/incidents/{id}`, `GET /api/soc/incidents/{id}/report`, `GET /api/soc/incidents.csv`

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `SOC_RETENTION_DAYS` | `90` | ลบ alert / agent record / incident ที่ปิดแล้วเก่ากว่านี้ |
| `SOC_AUTOSTART` | `on` | ดึง CTI feed และเริ่ม correlation ตั้งแต่เปิดเซิร์ฟเวอร์ (ไม่ต้องรอคนเปิด dashboard) |

### Analyst workspace: Tasks, Alerts (urgency/occurrences), Events by data source, Top observed threats

- **หน้าแรก** มี Pending alerts / Opened cases, ตาราง Alerts ที่รวม alert ซ้ำตาม (ชื่อ alert + host) พร้อมจำนวนครั้ง
  (occurrences) และ **urgency 0–100** = ฐานตามความรุนแรง (critical 85 / high 70 / medium 45 / low 20) + (occurrences−1, สูงสุด 10)
  + 5 ถ้าตรง CTI + 5 ถ้าอยู่ใน incident หลายโดเมน — สูตรนี้เป็นค่าตั้งต้น ควรปรับตามบริบทลูกค้า
- **Events by data source**: นับ record ที่เข้ามาแยกตามแหล่ง (เช่น `Elastic ECS · EDR process`) เก็บถาวรใน `soc2_counters`;
  ข้อมูลจำลองจะมีป้าย "(จำลอง)" และไม่ถูกบันทึก
- **Top observed threats**: เทคนิค MITRE ATT&CK/ATLAS ที่พบมากที่สุดใน 24 ชม. จาก alert ในหน้าต่างปัจจุบัน
- **Tasks**: ชื่องาน, รายละเอียด, ผู้รับผิดชอบ (ผู้ใช้ใน tenant เดียวกันเท่านั้น), สถานะ (รอดำเนินการ / รอข้อมูล / กำลังทำ /
  เสร็จแล้ว / ยกเลิก), กำหนดส่ง, ผูกกับ incident ได้; แยกตาม tenant และบันทึกทุกการเปลี่ยนแปลงใน audit log (`soc.task`)
- **ต้องดำเนินการ** (ปุ่มกระดิ่ง): งานที่มอบหมายให้ผู้ใช้ (เลยกำหนดขึ้นก่อน), incident ที่มอบหมายให้ และ incident critical ที่ยังไม่มีเจ้าของ

API: `GET /api/soc/overview`, `GET|POST /api/soc/tasks`, `PATCH /api/soc/tasks/{id}`, `GET /api/soc/assignees`,
`GET /api/soc/notifications`. Rate limit แยก: GET ใช้ `OSINT_READ_RATE_LIMIT` (ค่าเริ่ม 300/นาที/IP) เพื่อให้ widget
poll ได้ ส่วน POST/PATCH และการสแกน OSINT ยังใช้ `OSINT_RATE_LIMIT` (30/นาที/IP)

### Alerts, Events explorer, Threat Landscape และกฎการแจ้งเตือน

- **Alerts** (ทั้งหมด): Occurrences, Case, วันที่, สถานะ, **Verdict** (True/False positive, Benign — ตั้งได้ในหน้า incident),
  ผู้รับผิดชอบ, Entity, Urgency, **Detection type** (Built-in / CTI / Offensive-AI / AI-agent policy / Custom rule), Type (tactic),
  Threats; กรองตามสถานะ/ความรุนแรง/ช่วงเวลา/log จริง, เรียงตามล่าสุด/urgency/occurrences, แบ่งหน้า — `GET /api/soc/alerts`
- **Events**: ค้น log ดิบด้วย `field:value`, `-field:value` และคำค้นอิสระ พร้อม histogram (จริง vs จำลอง) และคำอธิบาย
  ที่อ่านง่ายต่อบรรทัด; log จริงเก็บใน `soc2_raw` ตาม `SOC_RAW_RETENTION_DAYS` (ค่าเริ่ม 7 วัน) — `GET /api/soc/events`
- **Threat Landscape**: Malware prevalence (ThreatFox — เฉพาะช่วงที่ export "recent" ครอบคลุม), CISA KEV ที่เพิ่มต่อสัปดาห์
  + CVE ล่าสุด, MITRE technique prevalence จาก alert ของ tenant และตาราง threat ที่พบ (framework / malware / CVE) พร้อมจำนวน
  IOC ที่เกี่ยวข้องใน ThreatFox — `GET /api/soc/landscape`. ไม่ใช่ telemetry ระดับโลก
- **กฎการแจ้งเตือน**: ความรุนแรงขั้นต่ำ, urgency ขั้นต่ำ, โดเมน, rule ID prefix, คำในชื่อ, เฉพาะ log จริง → ช่องทาง
  ในระบบ (กระดิ่ง) / Teams / LINE / Slack / webhook / email (เฉพาะที่ตั้งค่าบนเซิร์ฟเวอร์); ยิงครั้งเดียวต่อ incident ต่อระดับ
  ความรุนแรง, ทดสอบกับ incident ปัจจุบันได้ก่อนบันทึก — `GET|POST /api/soc/notify-rules`, `PUT|DELETE /api/soc/notify-rules/{id}`,
  `POST /api/soc/notify-rules/test`, `POST /api/soc/notifications/read` (สร้าง/แก้กฎต้องมีสิทธิ์ `rules.manage`)

### Cases, Query builder, Notebooks และ Rules catalog

- **Cases**: ทุก incident คือ case — ตารางพร้อม Priority, Verdict, Custom fields, Tags, ผู้รับผิดชอบ, ประเภท (Automatic จาก
  correlation / Manual ที่ analyst เปิดเอง); สร้าง case ด้วยมือ (`POST /api/soc/cases`), ตั้ง custom fields ของ tenant
  (`PUT /api/soc/case-fields`, สิทธิ์ `rules.manage`), ระดับความสำคัญของ asset 0–5 (`PUT /api/soc/assets/criticality`);
  หน้า case มีแท็บ Details / Alerts / Tasks / Events (log ดิบของ host+user ในช่วงเวลา case ±1 ชม.) / Notebooks.
  case ที่สร้างด้วยมือไม่ถูกรวม alert อัตโนมัติและไม่ถูกปิดเองเมื่อไม่มีความเคลื่อนไหว
- **Query builder** (`POST /api/soc/query`): `events | where kind == "logon" and user contains adm | count by host | limit 50`
  — where / sort / limit / count by / fields, ตัวดำเนินการ `== != contains startswith endswith > < in exists`; ตีความเอง
  ไม่มี eval หรือ regex จากผู้ใช้; บันทึก query ของ tenant ได้ (`/api/soc/queries`), export CSV (กัน formula injection)
- **Notebooks**: บันทึกการสืบสวนแบบ Markdown (render แบบ escape ทั้งหมดก่อน) ผูกกับ case ได้, ถังขยะ/กู้คืน,
  กันเขียนทับกันด้วย `base_updated_at` (409 ถ้ามีคนบันทึกก่อน) — `/api/soc/notebooks`
- **Rules catalog** (`GET /api/soc/rules/catalog`): OAI-001..014, AGT-001..012 และ custom rules พร้อม alerts 7 วัน,
  จำนวนที่ analyst ปฏิเสธ (verdict false positive / benign), quality score, MITRE coverage heatmap, ไฟล์ KQL/SPL ที่ส่งออกได้;
  เปิด/ปิด rule ราย tenant (`PUT /api/soc/rules/{id}/enabled`) — alert ของ rule ที่ปิดจะไม่ถูกสร้าง (นับไว้ใน `suppressed`)

### Intakes, Entities และ Assets

- **Intakes**: แหล่ง log แต่ละตัว (เช่น `HQ_Fortigate`, `สาขาบางนา_Windows`) มี key ของตัวเอง — log shipper ส่งเข้า
  `POST /api/soc/intake` ด้วย header `X-Intake-Key` โดยไม่ต้องถือ token ผู้ใช้; รูปแบบ log, tenant และ entity มาจาก intake;
  นับ valid / invalid (record ที่ parse ไม่ได้) / warning (timestamp หาย-อ่านไม่ได้-อยู่ในอนาคต หรือผูกกับ host/user ไม่ได้) รายวัน
  ดูย้อนหลัง 24 ชม. / 7 / 30 วัน; key เก็บเป็น SHA-256 แสดงครั้งเดียว, rotate และปิดใช้ได้ — `/api/soc/intakes`
- **Entities**: กลุ่มเจ้าของ intake (บริษัทลูก / สาขา / BU); alert ที่เกิดจาก intake จะมี `entity`; โหมด `monitor`
  เก็บ log อย่างเดียวไม่สร้าง alert (ใช้ช่วง onboarding / tuning) — `/api/soc/entities`
- **Assets**: host / บัญชีผู้ใช้ / AI agent ที่ค้นพบจาก log อัตโนมัติ พร้อมพบครั้งแรก-ล่าสุด, events, alerts, แหล่งที่เห็น;
  เพิ่มเอง, ใส่ tag, ตั้ง criticality 0–5 และ revoke ได้ — `GET /api/soc/assets`, `PUT /api/soc/assets` (สิทธิ์ `agents.manage`)
- **Rules catalog** เพิ่ม: ชนิด log ที่แต่ละ rule ต้องใช้ + กรองเฉพาะ rule ที่มี log เข้าระบบแล้ว, จำนวน IOC ที่ใช้งานอยู่จาก CTI,
  ปุ่ม "แจ้งเตือนเมื่อเจอ" สร้างกฎแจ้งเตือนของ rule นั้น

### Intelligence, IOC ของ tenant, Feeds (ส่งออก) และ Integrations

- **Intelligence** (`GET /api/soc/intel`): ค้น IOC รวมจาก ThreatFox, Feodo Tracker, CISA KEV, ThreatDefence agentic indicators
  และ IOC ของ tenant — ค้นหลายค่าพร้อมกัน (บรรทัดใหม่ / ,) รองรับแบบ defang, แสดง TLP, ความเชื่อมั่น, แหล่ง, threat และ
  **การพบใน tenant** (จำนวน log / alert / host ใน 7 วัน) พร้อมบอกค่าที่ไม่พบในฐานข้อมูล
- **IOC ของ tenant** (`POST /api/soc/iocs`, `POST /api/soc/iocs/delete`, สิทธิ์ `rules.manage`): เพิ่มทีละมาก ๆ พร้อม TLP,
  ความเชื่อมั่น, threat, ความรุนแรง, วันหมดอายุ
- **ตรวจจับ IOC ใน log จริง**: rule **IOC-001** (IOC ของ tenant) และ **IOC-002** (CTI feed สาธารณะ) เทียบ IP / IP:port / domain /
  URL / hash / user-agent ใน log ที่ ingest; 1 alert ต่อ indicator ต่อ host ต่อ 10 นาที; เปิด/ปิดได้ใน Rules catalog
- **Feeds (ส่งออก)** (`/api/soc/feeds`): เลือกชนิด, แหล่ง, ความเชื่อมั่นขั้นต่ำ, TLP สูงสุด (ไม่เกิน AMBER+STRICT — RED ไม่ถูกส่งออก),
  รูปแบบ STIX 2.1 / Text (บรรทัดละรายการ สำหรับ FortiGate Threat Feed, Palo Alto EDL) / CSV; URL `GET /feeds/<key>.<txt|json|csv>`
  มี key ในตัว (เก็บเป็น SHA-256, แสดงครั้งเดียว, หมุนได้), นับจำนวนครั้งที่ถูกดึงและ IP ล่าสุด, จำกัด 60 ครั้ง/นาที/IP
- **Integrations** (`GET /api/soc/integrations`): รายการสิ่งที่ระบบเชื่อมได้จริง (intake formats, CTI feeds, feeds ส่งออก,
  ช่องทางแจ้งเตือน, AI, enrichment, ไฟล์ KQL/SPL/Sigma) พร้อมสถานะที่คำนวณจากการตั้งค่าบนเซิร์ฟเวอร์และวิธีตั้งค่า

### SOC Assistant, IOC Collections, Graph explorations, Workspace settings

- **SOC Assistant** (ปุ่ม "✦ ถาม AI", `POST /api/assistant`, สิทธิ์ `ai.use`): Claude ตอบคำถามเกี่ยวกับข้อมูลของ tenant ผ่าน
  tool แบบอ่านอย่างเดียว 7 ตัว (alerts, cases, case detail, pipe query บน log ดิบ, intelligence, rules catalog, assets) ใน
  manual tool-use loop บน Messages API (`claude-opus-5-5`, server-side refusal fallback `fallbacks="default"`, สูงสุด 6 รอบ);
  ผลของ tool ถูกแทนชื่อผู้ใช้/อีเมล/IP ภายในด้วยนามแฝงก่อนส่งให้โมเดล และแปลงกลับในคำตอบ; ทุกคำถามบันทึก audit (`ai.assistant`)
  พร้อม tool ที่ใช้, token และค่าใช้จ่ายโดยประมาณ; ไม่มี API key → โหมดคำสั่งพื้นฐาน (เรียก tool ตรง ๆ ไม่ใช้ AI)
- **IOC Collections** (`/api/soc/ioc-collections`): ชุด IOC ตามแคมเปญ/incident, valid from / until, kill chain phase, นำเข้าไฟล์
  .txt/.csv, revoke รายตัว (`POST /api/soc/iocs/revoke` — IOC ที่ revoke จะไม่ถูกจับคู่ใน log), **telemetry report** ว่า IOC
  ใดใน collection เคยปรากฏใน log/alert ของ tenant (7/30/90 วัน) ดาวน์โหลด CSV ได้ — หนึ่ง IOC อยู่ได้หนึ่ง collection
- **Graph explorations** (`/api/soc/graph/expand`, `/api/soc/graphs`): เริ่มจาก host / account / indicator / case / threat / rule
  แล้วดับเบิลคลิกเพื่อขยายความเชื่อมโยงจาก alert, log ดิบ 7 วัน, case และ intelligence ของ tenant; ลากจัดตำแหน่งและบันทึกได้
- **Workspace settings** (`/api/soc/workspace`, แก้ไขต้องมีสิทธิ์ `users.manage`): ข้อมูลองค์กร (ชื่อนิติบุคคล, โดเมน, ที่ตั้ง,
  อุตสาหกรรม, ขนาด, ขนาดทีม security, ผู้ติดต่อ DPO) พร้อมป้าย "ข้อมูลยังไม่ครบ"; **Case templates** (`PUT /api/soc/case-templates`)
  เติม priority/tag และสร้าง Tasks ให้อัตโนมัติเมื่อสร้าง case จาก template
- หน้าแรกเพิ่ม: Ongoing alerts, แนวโน้ม % เทียบ 24 ชม. ก่อนหน้า, ความเห็นล่าสุดของ analyst, Cases ล่าสุด

### ขนาดข้อมูล (`SOC_SCALE`, ค่าเริ่ม 5)

ตัวคูณเดียวสำหรับทั้งข้อมูลจำลองและความจุข้อมูลจริง (ตั้ง `SOC_SCALE=1` เพื่อกลับเป็นขนาดเดิม, สูงสุด 20)

| มิติ | ×1 | ×5 |
|---|---|---|
| เครื่อง / ผู้ใช้จำลอง | 14 / 14 | 70 / 70 (เช่น `FIN-WS-114`, `finance.ops2`) |
| AI agent จำลอง | 5 | 25 (`support-copilot-2` …) |
| alert จำลองต่อนาที (วัดจริง) | ~100 | ~480 |
| แคมเปญโจมตีจำลองพร้อมกัน | 1 | สูงสุด 5 (คนละเครื่อง) |
| ประเทศต้นทางจำลอง | 10 | 50 |
| alert ในหน่วยความจำ / log ดิบ / agent audit | 300 / 5,000 / 2,000 | 1,500 / 25,000 / 10,000 |
| incident ในหน่วยความจำ / โหลดตอนเริ่ม | 200 | 1,000 |
| record ต่อการส่ง log หนึ่งครั้ง / ขนาด | 5,000 / 5 MB | 25,000 / 25 MB |
| asset สูงสุด / กล่องแจ้งเตือน / คำขออนุมัติที่เก็บ | 50,000 / 500 / 500 | 250,000 / 2,500 / 2,500 |
| IOC ต่อการเพิ่มหนึ่งครั้ง / สถานะ alert ที่เก็บ | 10,000 / 5,000 | 50,000 / 25,000 |

ไม่ได้คูณ: ระยะเก็บข้อมูล (`SOC_RETENTION_DAYS`, `SOC_RAW_RETENTION_DAYS` — นโยบาย PDPA และพื้นที่ disk), ขีดจำกัดต่อการค้นหา
หนึ่งครั้ง (กันหน่วยความจำเต็ม), จำนวนชนิดของ detection/แหล่งข้อมูล (ต้องเพิ่ม rule/parser จริง ไม่ใช่ตัวเลข)

 (Teams / LINE / Slack / Email / Webhook)

ตั้งค่าผ่าน environment variables (บน Render: service → **Environment**) — ไม่ต้องแก้โค้ด, secret ไม่ถูกเก็บใน repo

| ตัวแปร | ช่องทาง |
|---|---|
| `SOC_NOTIFY_TEAMS_URL` | Microsoft Teams — URL จาก Workflows "When a Teams webhook request is received" (ส่งเป็น Adaptive Card) |
| `SOC_NOTIFY_LINE_TOKEN` + `SOC_NOTIFY_LINE_TO` | LINE Messaging API — channel access token + userId/groupId ปลายทาง (LINE Notify ปิดบริการแล้ว) |
| `SOC_NOTIFY_SLACK_URL` | Slack incoming webhook |
| `SOC_NOTIFY_WEBHOOK_URL` | HTTPS endpoint ใดๆ (รับ JSON `{"event":"soc.incident","incident":{...}}`) เช่น SOAR / ระบบ ticket |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SOC_NOTIFY_EMAIL_TO` | Email (STARTTLS) |
| `SOC_NOTIFY_MIN_SEVERITY` | `high` (ค่าเริ่มต้น) / `critical` / `medium` |
| `SOC_NOTIFY_SIMULATED` | `off` (ค่าเริ่มต้น) — แจ้งเฉพาะ incident จาก log จริง |
| `SOC_NOTIFY_REDACT` | `on` = ปิดบังชื่อผู้ใช้ในข้อความ (ลดข้อมูลส่วนบุคคลที่ส่งไปแพลตฟอร์มแชตภายนอก) |
| `SOC_PUBLIC_URL` | เช่น `https://osint-toolkit-fepe.onrender.com` — ใส่ลิงก์เปิด incident ในข้อความ |
| `SOC_NOTIFY_MAX_PER_10MIN`, `SOC_NOTIFY_DEBOUNCE` | เพดานข้อความ (20 / 10 นาที) และช่วงรวบการเปลี่ยนแปลงของ incident เดียว (10 วินาที) |

- ส่งเมื่อ incident ถึงระดับขั้นต่ำครั้งแรก และส่งอีกครั้งเฉพาะเมื่อ**ยกระดับความรุนแรง**; จำสถานะไว้ใน DB จึงไม่ส่งซ้ำหลัง restart
- ปุ่ม "แจ้งเตือน: …" บนแถบด้านบนของ `/soc` = ส่งข้อความทดสอบ (บันทึกใน audit log); `GET /api/soc/notify` แสดงช่องทางและผลส่งล่าสุด (ไม่แสดง URL/token)
- ลิงก์ `…/soc#inc-<id>` เปิดหน้ารายละเอียด incident นั้นโดยตรง

### ผู้ใช้และสิทธิ์ (RBAC) — สิทธิ์ตามการกระทำ

สิทธิ์ตั้งชื่อตามการกระทำ (47 สิทธิ์ ใน 11 กลุ่ม — รายการเต็มและคำอธิบายภาษาไทยอยู่ที่ `GET /api/roles` และตารางในหน้า
"ผู้ใช้และสิทธิ์") ทุก endpoint ผูกกับสิทธิ์เดียว และมีเทสต์ตรวจว่าไม่มี endpoint ใดไม่มีการตรวจสิทธิ์

| กลุ่ม | สิทธิ์ |
|---|---|
| ข้อมูล SOC | `soc.read` `alerts.read` `events.read` `cases.read` `assets.read` `entities.read` |
| ค้นหาและวิเคราะห์ | `query.run` `notebooks.read` `notebooks.write` `soc.export` |
| จัดการเคส | `cases.create` `cases.update` `cases.assign` `cases.close` |
| จัดการ Alert | `alerts.acknowledge` `alerts.assign` `alerts.escalate` `alerts.close` |
| Threat Intelligence / OSINT | `threatintel.read` `threatintel.curate` `osint.scan` `osint.history` `osint.export` |
| กฎและการตรวจจับ | `rules.read` `rules.edit` `rules.publish` `rules.rollback` |
| Agentic AI | `agents.read` `agents.edit` `agents.approve` `agents.deploy` |
| AI | `ai.copilot` `ai.hunt` `ai.enrich` |
| การตอบสนอง | `respond.execute` `respond.approve` |
| ระบบและการกำกับดูแล | `assets.manage` `integrations.manage` `ingest.sources.manage` `ingest.submit` `governance.read` `governance.manage` |
| ผู้ใช้และการตรวจสอบ | `users.read` `users.manage` `roles.manage` `tokens.manage` `audit.read` |

- บทบาท: **viewer** (อ่านอย่างเดียว ไม่มีสิทธิ์ส่งออก) ⊂ **analyst** (ค้นหา วิเคราะห์ สร้าง/แก้/ปิด case, รับทราบ/ยกระดับ/ปิด alert,
  ร่าง rule, เสนอสิทธิ์ agent — ไม่มี `respond.execute`, `rules.publish`, `agents.deploy`, `cases.assign`) ⊂ **lead** (+ มอบหมาย,
  เผยแพร่/ย้อน rule, ขอและอนุมัติการตอบสนอง, อนุมัติสิทธิ์ agent, retire agent, `osint.export`, `audit.read`) ⊂ **admin** (+ ผู้ใช้
  บทบาท token การเชื่อมต่อ แหล่ง log นโยบาย); **ingest** มีแค่ `ingest.submit` (บัญชีบุคคลส่ง log ไม่ได้)
- **บทบาทกำหนดเอง** ต่อ tenant (`PUT/DELETE /api/roles/{name}`, สิทธิ์ `roles.manage`) — มอบได้เฉพาะสิทธิ์ที่ผู้สร้างมีอยู่เอง;
  การสร้างผู้ใช้หรือเปลี่ยนบทบาทก็ตรวจแบบเดียวกัน (ห้ามยกระดับสิทธิ์ตัวเอง/ผู้อื่นเกินตัว)
- ตรวจตามการกระทำจริง: แก้ case = `cases.update`, ปิด/เปิดใหม่ = `cases.close`, มอบหมายให้ผู้อื่น = `cases.assign`
  (รับงานเองใช้แค่ `cases.update`); ส่งออก CSV/รายงาน = `soc.export`
- **แยกผู้ขอกับผู้อนุมัติ** (นโยบายใน Governance, `GET/PUT /api/soc/policies`): การตอบสนอง (กักกัน/ปล่อย agent) และการเพิ่ม/แก้สิทธิ์
  AI agent เป็น "คำขอ" ที่ต้องให้อีกคนอนุมัติ (`/api/soc/response-requests`, `/api/soc/agents/requests`) — เปิดเป็นค่าเริ่มต้น;
  ผู้ขออนุมัติคำขอตัวเองไม่ได้; เลือกเปิดได้ว่าผู้แก้ rule ล่าสุดเผยแพร่เองไม่ได้
- **Rule versioning**: แก้ rule ที่มีอยู่ = draft (เวอร์ชันที่ใช้งานยังทำงานต่อ), `rules.publish` เผยแพร่ draft เป็นเวอร์ชันใหม่,
  `rules.rollback` ย้อนเวอร์ชัน (`POST /api/soc/rules/{id}/rollback`) — เก็บ 20 เวอร์ชันล่าสุด
- **Alert actions** (`POST /api/soc/alerts/action`): รับทราบ / มอบหมาย / ยกระดับ (เพิ่ม priority ของ case หรือสร้าง case ใหม่) /
  ปิด (ต้องมีเหตุผล) / เปิดใหม่ — ไม่มีสิทธิ์สั่งตอบโต้ระบบ; alert ที่ปิดแล้วเกิดซ้ำจะกลับเป็น "ใหม่"
- **Agent lifecycle** (`POST /api/soc/agents/{id}/lifecycle`, `agents.deploy`): retire agent — กิจกรรมหลังจากนั้นถูกบล็อกและแจ้ง AGT-011
- ทุกการกระทำข้างต้นบันทึกใน audit log พร้อมชื่อผู้ขอ/ผู้อนุมัติ

### AI SOC Copilot (เฟส 2)

ในหน้ารายละเอียด incident: **สรุปด้วย AI** (สรุปเหตุการณ์ · การประเมิน · AI Incident Timeline · ขั้นตอนรับมือเรียงตามความเร่งด่วน · คำถามที่ต้องหาคำตอบต่อ) และ **ถาม Copilot** แบบสนทนาเกี่ยวกับ incident นั้น; สรุปถูกเก็บไว้กับ incident และใส่ในรายงาน HTML/PDF

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | API key ของ Claude (ไม่ตั้ง = ใช้สรุปแบบกฎ/playbook ไม่มีการส่งข้อมูลออก) |
| `SOC_AI_MODEL` | `claude-opus-5-5` | โมเดลที่ใช้ |
| `SOC_AI_EFFORT` | `medium` | ระดับการคิด (`low`/`medium`/`high`) — สูงขึ้น = ช้าและแพงขึ้น |
| `SOC_AI_REDACT` | `on` | ปิดบัง**ชื่อผู้ใช้ อีเมล และ IP ภายใน (RFC 1918)** ด้วยนามแฝง (USER_1, IP_1 …) ก่อนส่ง แล้วแปลงกลับในเครื่อง |

- เปิด server-side **refusal fallback** (`fallbacks="default"`) — ถ้าโมเดลปฏิเสธเนื้อหาด้านความปลอดภัย API จะส่งต่อโมเดลสำรองที่ Anthropic แนะนำให้อัตโนมัติ; ถ้ายังปฏิเสธ/เรียก API ไม่ได้ ระบบใช้สรุปแบบกฎแทนและแจ้งเหตุผล
- ข้อมูล incident ถูกส่งเป็น "ข้อมูลที่ไม่น่าเชื่อถือ" (กัน prompt injection จาก UA/command line/prompt ของผู้โจมตี)
- สิทธิ์ `ai.use` (analyst ขึ้นไป); ทุกการเรียกบันทึกใน audit log (ผู้ขอ, โมเดล, ปิดบังข้อมูลหรือไม่, จำนวน token)
- ผลจาก AI เป็นข้อเสนอ ต้องให้ analyst ตรวจสอบก่อนตัดสินใจ

### เฟส 3: AI Threat Hunting, Threat Enrichment และ Attack Chains

| ฟีเจอร์ | ทำงานอย่างไร | ไม่มี API key |
|---|---|---|
| **Natural Language Hunting** | Claude แปลงคำถาม (ไทย/อังกฤษ) เป็น*แผนค้นหาแบบมีโครงสร้าง* (JSON schema) แล้วระบบค้นในข้อมูลของเราเอง — **AI ไม่เห็นข้อมูล log** เห็นแค่คำถาม (ปิดบังชื่อผู้ใช้แล้ว) และรายชื่อฟิลด์; พร้อมเสนอ KQL สำหรับ Defender/Sentinel | ค้นแบบ `field:value` + คำค้นทุกฟิลด์ |
| **AI Threat Enrichment** | ค้น IOC ในทุกฟีด (CISA KEV, Feodo, ThreatFox, agentic-attack-detections, รายชื่อ AI API/OAST) และเหตุการณ์ในระบบก่อน แล้วให้ Claude อธิบาย/ประเมิน/แนะนำการรับมือ**จากหลักฐานที่พบเท่านั้น** | แสดงผลค้นจากฟีดและ sightings |
| **Attack Chain Analysis** | เชื่อม incident ที่มีเครื่อง บัญชี IP ผู้โจมตี AI agent หรือ IOC ร่วมกันภายใน 24 ชม. เป็นเส้นทางการโจมตี (อัลกอริทึม ไม่ใช้ AI) แสดง kill-chain coverage และกราฟเวลา; ปุ่มให้ Claude เล่าเส้นทาง | ใช้ได้เต็ม (เล่าเรื่องใช้ playbook) |

- ข้อมูลจริงกับข้อมูลจำลองไม่ถูกเชื่อมเป็นเส้นทางเดียวกัน; บัญชีว่าง/unknown ไม่ใช้เป็นตัวเชื่อม
- สิทธิ์: hunting/enrichment/AI = `ai.use` (analyst+), ดู attack chains = `soc.read`; ทุกการเรียกลง audit log
- API: `POST /api/soc/hunt/nl`, `POST /api/soc/enrich`, `GET /api/soc/chains`, `POST /api/soc/chains/{id}/ai`

### เฟส 4: AI Rule Assistant, Agent Risk Scoring, Response Plans

- **AI Rule Assistant** (การ์ด "AI Rule Assistant"): อธิบายสิ่งที่อยากตรวจจับเป็นภาษาไทย → Claude ร่าง
  *กฎสำหรับระบบ* (ภาษากฎปลอดภัย ไม่รันโค้ด: `kind`, `conditions` แบบ contains/equals/regex/in/gte/lte, `threshold` นับครั้งในช่วงเวลา) +
  **Sigma / KQL / SPL** + กรณีทดสอบ (ควรตรง/ไม่ควรตรง) + false positive ที่อาจเกิด → ระบบ **ตรวจรูปแบบ** (รวม Sigma YAML และกัน regex ReDoS),
  **รันกรณีทดสอบ** และ **ย้อนทดสอบ** กับ record ล่าสุด 5,000 รายการ เพื่อดูว่าจะแจ้งเตือนถี่แค่ไหน → แก้ JSON แล้วทดสอบซ้ำได้ →
  บันทึกเป็น `CUS-xxx` (ปิดอยู่) → **หัวหน้าทีม (`rules.manage`) เปิดใช้** แล้วกฎจะตรวจ log ทุกรายการ (ไม่มี key ก็ "เขียนกฎเอง" ได้)
- **Agent Risk Scoring**: คะแนน 0–100 ต่อ agent แยกปัจจัยที่อธิบายได้ — exposure (สิทธิ์อ่อนไหว, shell, egress), governance
  (ไม่ลงทะเบียน, ไม่มีเจ้าของ, ไม่มี MCP allowlist), behaviour (detection 24 ชม., ถูกปฏิเสธ tool, prompt injection) — ชี้ที่คอลัมน์ Risk เพื่อดูเหตุผล
- **Response plan** ในหน้ารายละเอียด incident: checklist ตาม NIST (Containment → Eradication → Recovery → Notification → Lessons learned)
  สร้างจาก rule/MITRE playbook; ติ๊กแล้วบันทึกผู้ทำ/เวลาใน incident และ audit log; ถ้าเข้าข่ายข้อมูลส่วนบุคคลรั่ว (OAI-010/011, AGT-004/009, T1567 …)
  แสดง **นาฬิกา 72 ชม. ตาม PDPA ม.37(4)** — นับจากเวลาตรวจพบครั้งแรก ควรยืนยันเวลา "ทราบเหตุ" กับ DPO
- API: `POST /api/soc/rules/draft`, `POST /api/soc/rules/test`, `GET/POST /api/soc/rules`, `PATCH /api/soc/rules/{id}`,
  `GET /api/soc/agents/risk`, `GET /api/soc/incidents/{id}/response`, `POST /api/soc/incidents/{id}/response/{step}`

### เฟส 5: Multi-Tenant, Governance, AI Evaluation, HA/DR

- **Multi-tenant (MSSP)**: ข้อมูลทุกประเภทแยกตาม tenant (engine แยก, ฐานข้อมูลกรองตาม tenant ทุกคำสั่ง); ผู้ใช้ผูกกับ tenant —
  บัญชี `ingest` ของลูกค้าแต่ละรายส่ง log เข้า tenant ของตัวเองอัตโนมัติ; ทีมแพลตฟอร์ม (ผู้ใช้ tenant `*` หรือ bootstrap key) สลับ tenant ได้ด้วย
  header `X-Tenant` หรือตัวเลือกในแถบซ้าย; tenant ลูกค้าไม่มีข้อมูลจำลอง; ข้อมูลเดิมย้ายเข้า tenant `default` อัตโนมัติ
- **Governance**: audit log แบบ **hash chain** (ตรวจได้ว่ามีการแก้/ลบย้อนหลังหรือไม่), ดู/Export CSV audit log ตาม tenant,
  รายงานการใช้ AI (จำนวนครั้ง, token, ต้นทุนโดยประมาณ, fallback, คะแนนจาก analyst)
- **AI Evaluation**: ตรวจ **grounding** ทุกคำตอบ (host/IP/CVE/technique/rule ที่ AI พูดถึงแต่ไม่มีในข้อมูล → แสดงคำเตือน),
  ปุ่ม 👍/👎 ให้ analyst ให้คะแนน, ชุดทดสอบ offline `python -m evals.ai_eval` กับ incident สังเคราะห์ (schema, การประเมิน, grounding,
  privacy — ตรวจว่าไม่มีชื่อจริงหลุดออกไป, ความเร่งด่วน, ภาษาไทย) — ใช้ API จริง มีค่าใช้จ่าย
- **HA/DR**: `/healthz`, `/readyz`, backup อัตโนมัติ (`SOC_BACKUP_DIR`), ดาวน์โหลด backup, คู่มือกู้คืนและตัวเลือกโครงสร้าง → [`docs/DR_RUNBOOK.md`](docs/DR_RUNBOOK.md)

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

ทดสอบ: `.venv/bin/pytest -q` (126 tests, mock network ทั้งหมด)

## ข้อจำกัดที่ทราบ
- `.th` ไม่มี RDAP → ระบบแจ้งให้ใช้ THNIC WHOIS (ยังไม่ได้ integrate)
- Username checker อาจคลาดเคลื่อนเมื่อแพลตฟอร์มเปลี่ยนหน้าเว็บ หรือบล็อกด้วย 403/429 (แสดงเป็น `unknown`)
- Rate limit อยู่ใน memory (รีเซ็ตเมื่อรีสตาร์ต, ไม่แชร์ข้าม instance)
- SSRF guard ไม่กัน DNS rebinding 100% — production ควรบล็อก private range ที่ egress firewall ด้วย
- ยังไม่มีระบบผู้ใช้/RBAC (ใช้ API key ร่วม)
