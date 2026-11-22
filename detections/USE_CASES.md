# Detection use cases — Agentic AI / AI-driven attacks

Priority = ผลกระทบถ้าเป็นเหตุจริง × ความแม่นยำของสัญญาณ (false positive ต่ำ = สูง) × ความเร็วที่ต้องตอบสนอง
(ข้อเสนอเริ่มต้น ควรปรับตามบริบทลูกค้า เช่น หน่วยงานกำกับ/โครงสร้างพื้นฐานสำคัญ ยกระดับได้)

| # | Detection Use Case | แหล่ง Log | Priority | Rule ในระบบ | เหตุผลของ Priority |
|---|---|---|---|---|---|
| 1 | AI Agent เรียก Security Tools แบบ Auto-Approve | EDR, Process | **P1 Critical** | OAI-001 (+ OAI-003, OAI-005) | สัญญาณเฉพาะเจาะจงมาก (agent CLI ที่ปิดการอนุมัติ + เครื่องมือโจมตี) แทบไม่มีเหตุผลปกติบนเครื่อง production; คือรูปแบบหลักของ ARTEX/Cairn/Hermes |
| 2 | Tool Execution Burst | EDR, SIEM | **P2 High** | OAI-003 (process), AGT-010 (tool call ของ agent) | ความเร็วระดับเครื่องจักรบ่งชี้ automation แต่ทีม pentest/DevOps ทำให้เกิดได้ — ต้องมี allowlist |
| 3 | AI API Calls จากเซิร์ฟเวอร์ที่ไม่ได้รับอนุญาต | DNS, Proxy | **P2 High** (ผู้ให้บริการจีน = High อัตโนมัติ; ลูกค้ากำกับดูแล/ข้อมูลอ่อนไหว ยกเป็น P1) | OAI-002 | อาจเป็น shadow AI หรือ agent โจมตีที่ใช้โมเดลภายนอก; ประเด็น PDPA การโอนข้อมูลข้ามประเทศ (มาตรา 28–29) |
| 4 | Web/API Reconnaissance Burst | WAF, NDR | **P3 Medium** (เป็น P1 เมื่อตามด้วย exploit — OAI-005) | OAI-008 | สแกนจาก internet เกิดตลอดเวลา; มีค่าเมื่อ correlate กับขั้นถัดไป |
| 5 | Lateral Movement Fan-out | EDR, AD | **P1 Critical** | OAI-009 | ผู้โจมตีอยู่ในเครือข่ายแล้ว ความเสียหายขยายเร็ว (ransomware/DCSync) |
| 6 | Rotating Proxy Reconnaissance | WAF, SIEM | **P3 Medium** | OAI-004 | บ่งชี้ความตั้งใจหลบเลี่ยง แต่ยังเป็นขั้นสำรวจ; ใช้ยกระดับ incident เดียวกัน |
| 7 | Suspicious Database Access & Exfiltration | DB Audit, DLP | **P1 Critical** (dump/bulk read อย่างเดียว = P2) | OAI-010 → OAI-011 | ข้อมูลรั่ว = ผลกระทบสูงสุด และมีหน้าที่แจ้ง สคส. ภายใน 72 ชม. ตาม PDPA มาตรา 37(4) หากมีความเสี่ยงต่อสิทธิของเจ้าของข้อมูล |
| 8 | MCP Tool Invocation ผิดนโยบาย | AI Gateway, MCP Logs | **P2 High** (MCP server เครื่องมือโจมตี เช่น hexstrike = P1 Critical) | AGT-012 (+ AGT-001 scope) | agent ใช้เครื่องมือนอกขอบเขตที่อนุมัติ — จุดเริ่มของ prompt-injection / tool abuse |

SLA ตอบสนองที่แนะนำ: P1 ≤ 15 นาที · P2 ≤ 1 ชั่วโมง · P3 ภายในวันทำการ

## Mapping สู่ระบบ
| Use case | ส่ง log เข้า `/api/soc/ingest` เป็น | Hunting query |
|---|---|---|
| 1, 2 | `process` (Defender `DeviceProcessEvents`, ECS process start) | `01`, `03`, `11`, Sigma `21` |
| 3 | `net` (DNS / proxy / `DeviceNetworkEvents`) | `02`, `12`, Sigma `22` |
| 4, 6 | `http` (WAF / web access log) | `04`, `07`, `13`, Sigma `23` |
| 5 | `net` (admin ports) และ `logon` (AD 4624/4625, `DeviceLogonEvents`, ECS authentication) | `08`, `14` |
| 7 | `db` (DB audit: statement, rows, bytes) และ `dlp` (DLP/CASB: dest, bytes, classification) | — (schema DB audit ต่างกันตามผลิตภัณฑ์) |
| 8 | AI-agent audit `tool_call` พร้อม `mcp_server` (หรือชื่อ tool รูปแบบ `mcp__server__tool`); ลงทะเบียน allowlist ด้วย `mcp_servers` ที่ `/api/soc/agents/register` | — |

## เกณฑ์ (ปรับได้ใน `app/offensive_ai.py`)
- OAI-008: ≥ 60 requests/นาที จาก IP เดียวต่อเป้าหมาย และ (error ≥ 50% หรือ path ต่างกัน ≥ 40)
- OAI-009: ≥ 10 เครื่องปลายทางใน 10 นาที (พอร์ต 22/135/139/445/3389/5985/5986 หรือ network/RDP logon) นับทั้งรายเครื่องต้นทางและรายบัญชี
- OAI-010: คำสั่ง dump/export (mysqldump, pg_dump, INTO OUTFILE, COPY … TO, BACKUP DATABASE, bcp out, xp_cmdshell, expdp) หรืออ่าน ≥ 100,000 แถว / ≥ 50 MB ใน 10 นาทีต่อผู้ใช้
- OAI-011: ส่งข้อมูลออกภายนอก ≥ 50 MB หรือ DLP จัดชั้นความลับ ภายใน 30 นาทีหลัง OAI-010 ของผู้ใช้/เครื่องเดียวกัน (critical); DLP ข้อมูลลับออกภายนอกโดยลำพัง (high)
- AGT-012: MCP server ไม่อยู่ใน allowlist ของ agent (high) หรือเป็น tool server เชิงรุก (critical)

สถานะ: กฎทดสอบกับข้อมูลสังเคราะห์ (unit test + demo) แล้ว ยังไม่ได้ทดสอบกับ log จริงของลูกค้า — ควรรันโหมด hunting และปรับเกณฑ์ 1–2 สัปดาห์ก่อนเปิด alert

## Framework → พฤติกรรมเด่น → กฎที่ครอบคลุม

| Framework | พฤติกรรมเด่น (ที่ต้องเฝ้าระวัง) | กฎหลัก | สัญญาณเสริม |
|---|---|---|---|
| ARTEX | Multi-step Intrusion, Autonomous Execution | OAI-005 chain, OAI-001 approvals off | OAI-012 swarm, OAI-009 fan-out, OAI-006 IOC |
| AntiFox | Fork-specific Indicators และ Behavior | OAI-006 (indicator ที่ระบุ AntiFox แยกนับเป็นการ์ดของตัวเอง) | พฤติกรรมเดียวกับ ARTEX: OAI-005, OAI-001 |
| CAIRN | Multi-Agent Coordination, Tool Orchestration | **OAI-012** หลาย agent CLI (approvals off) บนเครื่องเดียว | OAI-001, OAI-003, OAI-006 |
| PentAGI | Reconnaissance, Pentest Tool Chains | OAI-003 fan-out, OAI-005 chain | OAI-008 recon burst, OAI-006 |
| HexStrike | MCP-mediated Security Tool Invocation | **OAI-013** เครื่องมือโจมตีที่ MCP server เป็นผู้เรียก (hexstrike = critical) | AGT-012 MCP ผิดนโยบาย, OAI-003, OAI-006 |
| CyberStrikeAI | Orchestrated Tool Execution | OAI-003, OAI-005 | OAI-007 OAST, OAI-006 (webshell UA, implant header) |
| Strix | Web/API Security Testing Patterns | OAI-008 recon burst, OAI-004 rotating proxy | OAI-007 interactsh, OAI-006 sandbox image |
| Hermes Agent | Shell Execution, External Tool Access | **OAI-014** download-and-execute / reverse shell / encoded / inline code จาก agent | OAI-001 (`--yolo`, `HERMES_YOLO_MODE`), AGT-003, OAI-002 |
| Agent Zero | Dynamic Code Execution, Agent Workflows | **OAI-014** (agent runtime เช่น `run_ui.py`) | AGT-003, OAI-006 |

เกณฑ์ใหม่: OAI-012 = agent CLI ต่างชนิด ≥ 2 หรือ ≥ 3 instance ในโหมดปิดการอนุมัติบนเครื่องเดียวภายใน 10 นาที ·
OAI-013 = เครื่องมือโจมตีที่มีบรรพบุรุษเป็น MCP server (`hexstrike_server.py`, `mcp-server`, `fastmcp` …) ·
OAI-014 = ภายใต้ agent: `curl|wget … | sh/python`, `/dev/tcp`/`nc -e` (critical), `base64 -d |`/`-enc`, `python -c … exec/socket/subprocess`

KQL: `09_agent_swarm_mcp_dynamic_code.kql`
