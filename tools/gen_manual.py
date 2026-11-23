"""Fill the generated sections of docs/USER_MANUAL.md from the source code.

    python tools/gen_manual.py           # rewrite the generated blocks
    python tools/gen_manual.py --check   # exit 1 if the manual is out of date (used by the test suite)

Generated: glossary (data below), permissions and roles (app.rbac), detection rules (app.offensive_ai,
app.agent_detect, app.intel), API routes with their permission (app/main.py), environment variables (os.getenv calls).
"""
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("OSINT_DB_PATH", "/tmp/gen_manual.db")
MANUAL = ROOT / "docs" / "USER_MANUAL.md"

# (term, Thai translation, meaning in this system)
GLOSSARY = [
    ("Acknowledge", "รับทราบ", "ยืนยันว่าเห็น alert แล้ว ไม่นับเป็น Pending"),
    ("Agent (AI agent)", "เอเจนต์ AI", "โปรแกรม AI ที่เรียกใช้เครื่องมือ/คำสั่งได้เอง เช่น copilot, RPA bot"),
    ("Agent inventory", "ทะเบียนเอเจนต์", "รายการ AI agent ที่ลงทะเบียน พร้อมสิทธิ์ (scope) ที่อนุญาต"),
    ("Agentic AI", "AI แบบเอเจนต์", "AI ที่ทำงานหลายขั้นตอนเองโดยเรียกเครื่องมือ"),
    ("Alert", "การแจ้งเตือนภัย", "ผลจาก detection rule 1 ครั้ง"),
    ("Alert generation mode", "โหมดการสร้าง alert", "automatic = ตรวจจับปกติ, monitor = เก็บ log อย่างเดียว"),
    ("Allowlist", "รายการที่อนุญาต", "รายการค่าที่ยอมรับ เช่น ปลายทางที่ agent ออกไปได้ (egress)"),
    ("API", "ส่วนต่อประสานโปรแกรม", "ช่องทางให้โปรแกรมอื่นเรียกใช้ระบบ"),
    ("API key / Token", "กุญแจเข้าระบบ / โทเคน", "รหัสลับส่วนตัวใช้ยืนยันตัวตนแทนรหัสผ่าน แสดงครั้งเดียว"),
    ("Approve", "อนุมัติ", "ผู้มีสิทธิ์คนที่สองยืนยันคำขอ (four-eyes)"),
    ("Asset", "สินทรัพย์", "เครื่อง บัญชีผู้ใช้ หรือ AI agent ที่พบในระบบ"),
    ("Assignee", "ผู้รับผิดชอบ", "ผู้ใช้ที่ได้รับมอบหมาย case/alert/งาน"),
    ("ATT&CK (MITRE)", "กรอบเทคนิคการโจมตี MITRE", "ฐานความรู้ยุทธวิธี (tactic) และเทคนิค (technique) ของผู้โจมตี เช่น T1059"),
    ("ATLAS (MITRE)", "กรอบภัยต่อระบบ AI", "ฐานความรู้การโจมตีระบบ AI เช่น prompt injection (AML.T0051)"),
    ("Attack chain", "ห่วงโซ่การโจมตี", "หลาย incident ที่เชื่อมกันด้วยเครื่อง/บัญชี/IP เดียวกันใน 24 ชม."),
    ("Audit log", "บันทึกการตรวจสอบ", "บันทึกว่าใครทำอะไรเมื่อไร ป้องกันการแก้ย้อนหลังด้วย hash chain"),
    ("Backtest", "การทดสอบย้อนหลัง", "รัน rule กับข้อมูลที่ผ่านมาเพื่อประเมินจำนวน alert"),
    ("Benign", "ไม่เป็นอันตราย", "verdict: เหตุการณ์จริงแต่ถูกต้องตามธุรกิจ"),
    ("Break-glass key", "กุญแจฉุกเฉิน", "OSINT_API_KEY ใช้ตั้งค่าเริ่มต้น ไม่ระบุตัวบุคคล"),
    ("Brute force", "การเดารหัสผ่านแบบไล่ทุกค่า", "การลองรหัสผ่านซ้ำจำนวนมาก (T1110)"),
    ("C2 (Command and Control)", "เครื่องสั่งการของผู้โจมตี", "เซิร์ฟเวอร์ที่ malware ติดต่อเพื่อรับคำสั่ง"),
    ("Case", "เคส", "หน่วยงานสืบสวน 1 เรื่อง (incident = case)"),
    ("Case template", "แม่แบบเคส", "ค่าตั้งต้นของ case ด้วยมือ พร้อมงานที่สร้างอัตโนมัติ"),
    ("CERT / สคส.", "สำนักงานคณะกรรมการคุ้มครองข้อมูลส่วนบุคคล", "หน่วยงานที่ต้องแจ้งเหตุละเมิดข้อมูลส่วนบุคคลภายใน 72 ชม."),
    ("Confidence", "ความเชื่อมั่น", "คะแนน 0–100 ว่า IOC น่าเชื่อถือเพียงใด"),
    ("Containment", "การกักกัน", "หยุดการแพร่กระจาย เช่น เพิกถอน token ของ agent"),
    ("Coordinated attack", "การโจมตีประสานหลายโดเมน", "incident ≥ 2 โดเมนที่มี alert ระดับ high ขึ้นไป"),
    ("Correlation", "การเชื่อมโยงเหตุการณ์", "รวม alert ที่เครื่องหรือผู้ใช้เดียวกันภายใน 30 นาทีเป็น incident"),
    ("Criticality", "ระดับความสำคัญของสินทรัพย์", "0–5 ยิ่งสูงยิ่งต้องปกป้อง"),
    ("CSV", "ไฟล์ข้อมูลคั่นด้วยจุลภาค", "ไฟล์ตารางที่เปิดด้วย Excel ได้"),
    ("CT log (Certificate Transparency)", "บันทึกความโปร่งใสของใบรับรอง", "บันทึกสาธารณะของใบรับรอง SSL ใช้หา subdomain และโดเมนเลียนแบบ"),
    ("CTI (Cyber Threat Intelligence)", "ข่าวกรองภัยคุกคามไซเบอร์", "ข้อมูลภัยคุกคามจากแหล่งภายนอก เช่น IOC, CVE ที่ถูกใช้โจมตี"),
    ("Custom field", "ช่องข้อมูลกำหนดเอง", "ช่องเพิ่มเติมของ case ที่แต่ละ tenant กำหนด"),
    ("Custom rule (CUS)", "กฎที่สร้างเอง", "detection rule ที่ tenant สร้าง รหัส CUS-xxx"),
    ("CVE", "รหัสช่องโหว่สากล", "รหัสอ้างอิงช่องโหว่ เช่น CVE-2026-1234"),
    ("Dashboard", "แดชบอร์ด", "หน้าสรุปภาพรวม"),
    ("Data source", "แหล่งข้อมูล", "ระบบที่ส่ง log เช่น EDR, firewall"),
    ("Debounce", "หน่วงการแจ้งซ้ำ", "รวมการเปลี่ยนแปลงในช่วงสั้นๆ เป็นการแจ้งเตือนครั้งเดียว"),
    ("Defang", "ทำให้ลิงก์กดไม่ได้", "เขียน IOC แบบ evil[.]com / hxxp:// เพื่อความปลอดภัย"),
    ("Detection rule", "กฎตรวจจับ", "เงื่อนไขที่เมื่อตรงกับ log จะสร้าง alert"),
    ("Detection type", "ประเภทการตรวจจับ", "Built-in, CTI/IOC, Offensive-AI, AI-agent policy, Custom"),
    ("DLP (Data Loss Prevention)", "การป้องกันข้อมูลรั่วไหล", "ระบบตรวจการส่งข้อมูลสำคัญออกนอกองค์กร"),
    ("DNS", "ระบบชื่อโดเมน", "แปลงชื่อโดเมนเป็น IP"),
    ("DPO", "เจ้าหน้าที่คุ้มครองข้อมูลส่วนบุคคล", "ผู้ติดต่อด้าน PDPA ขององค์กร"),
    ("Draft", "ฉบับร่าง", "การแก้ rule ที่ยังไม่มีผลจนกว่าจะเผยแพร่"),
    ("Due date", "กำหนดส่ง", "วันที่งานต้องเสร็จ"),
    ("ECS (Elastic Common Schema)", "รูปแบบ log กลางของ Elastic", "รูปแบบ log จาก Beats/Elastic Agent"),
    ("EDR (Endpoint Detection and Response)", "การตรวจจับและตอบสนองที่เครื่องปลายทาง", "ระบบเฝ้าระวังเครื่องคอมพิวเตอร์/เซิร์ฟเวอร์"),
    ("Egress", "การส่งออกเครือข่าย", "การเชื่อมต่อออกไปภายนอก"),
    ("Endpoint", "เครื่องปลายทาง", "คอมพิวเตอร์ โน้ตบุ๊ก หรือเซิร์ฟเวอร์"),
    ("Enrichment", "การเสริมข้อมูล", "เพิ่มบริบทให้ IOC จาก CTI และ log ภายใน"),
    ("Entity", "หน่วยงานเจ้าของข้อมูล", "บริษัทลูก/สาขา/หน่วยธุรกิจที่เป็นเจ้าของ intake"),
    ("Escalate", "ยกระดับ", "เพิ่ม priority ของ case หรือสร้าง case จาก alert"),
    ("Event", "เหตุการณ์ / log", "บันทึกดิบ 1 รายการจากแหล่งข้อมูล"),
    ("Exfiltration", "การลักลอบนำข้อมูลออก", "การส่งข้อมูลออกนอกองค์กรโดยไม่ได้รับอนุญาต (T1567)"),
    ("Exploit", "การใช้ช่องโหว่", "การโจมตีผ่านช่องโหว่ของระบบ"),
    ("Export", "ส่งออก", "ดาวน์โหลดข้อมูลเป็นไฟล์ (ต้องมีสิทธิ์ export)"),
    ("Fallback", "ทางสำรอง", "เมื่อ AI ใช้ไม่ได้ ระบบใช้วิธีแบบกฎแทน"),
    ("False positive", "การแจ้งเตือนผิด", "alert ที่ไม่ใช่ภัยจริง"),
    ("Feed", "ฟีดข้อมูล", "ช่องทางรับ/ส่งรายการ IOC ต่อเนื่อง"),
    ("Firewall", "ไฟร์วอลล์", "อุปกรณ์ควบคุมการรับส่งเครือข่าย"),
    ("Four-eyes principle", "หลักสี่ตา (ผู้ขอกับผู้อนุมัติต้องเป็นคนละคน)", "การกระทำสำคัญต้องมีคนที่สองอนุมัติ"),
    ("Framework (offensive AI)", "เฟรมเวิร์กโจมตีด้วย AI", "เครื่องมือโจมตีที่ขับเคลื่อนด้วย AI agent เช่น HexStrike, PentAGI"),
    ("Governance", "การกำกับดูแล", "นโยบาย การตรวจสอบ และการควบคุมการใช้ระบบ"),
    ("Graph exploration", "การสำรวจความเชื่อมโยงแบบกราฟ", "ไล่ความสัมพันธ์ระหว่างเครื่อง บัญชี IOC case"),
    ("Grounding check", "การตรวจการอ้างอิงของ AI", "ตรวจว่าสิ่งที่ AI อ้างมีอยู่จริงในข้อมูล"),
    ("Hash", "ค่าแฮช", "ลายนิ้วมือของไฟล์ (MD5/SHA-1/SHA-256) หรือค่าที่ใช้เก็บ token อย่างปลอดภัย"),
    ("Hash chain", "ห่วงโซ่แฮช", "แต่ละรายการ audit log ผูกกับรายการก่อนหน้า แก้ย้อนหลังแล้วตรวจพบได้"),
    ("Homoglyph", "ตัวอักษรหน้าตาคล้ายกัน", "เช่น 0 กับ o ใช้ทำโดเมนเลียนแบบ"),
    ("Host", "เครื่อง", "คอมพิวเตอร์หรือเซิร์ฟเวอร์"),
    ("Hunting (Threat hunting)", "การไล่ล่าภัยคุกคาม", "การค้นหาภัยเชิงรุกที่ rule อาจยังจับไม่ได้"),
    ("Incident", "เหตุการณ์ด้านความปลอดภัย", "กลุ่ม alert ที่เชื่อมโยงกัน"),
    ("Indicator", "ตัวบ่งชี้", "ค่าที่ใช้ตรวจหาภัย (ดู IOC)"),
    ("Ingest", "การนำเข้าข้อมูล", "การรับ log เข้าระบบ"),
    ("Intake", "จุดรับ log", "แหล่ง log หนึ่งตัวพร้อม key ของตัวเอง"),
    ("Integration", "การเชื่อมต่อระบบ", "ระบบภายนอกที่เชื่อมได้ เช่น Teams, CTI feed"),
    ("Invalid event", "เหตุการณ์ที่อ่านไม่ได้", "record ที่ระบบ parse ไม่ได้ จึงถูกปฏิเสธ"),
    ("IOC (Indicator of Compromise)", "ตัวบ่งชี้การถูกบุกรุก", "IP, โดเมน, URL, hash ที่เกี่ยวกับการโจมตี"),
    ("IOC collection", "ชุด IOC", "กลุ่ม IOC ของเราตามแคมเปญหรือ incident"),
    ("JSON / NDJSON", "รูปแบบข้อมูล JSON / JSON บรรทัดละรายการ", "รูปแบบข้อมูลที่ใช้ส่ง log"),
    ("KEV (Known Exploited Vulnerabilities)", "ช่องโหว่ที่ถูกใช้โจมตีจริง", "รายการของ CISA ที่ควรแก้ไขก่อน"),
    ("Kill chain", "ลำดับขั้นการโจมตี", "ขั้นตอนตั้งแต่สอดแนมจนบรรลุเป้าหมาย"),
    ("KPI", "ตัวชี้วัดหลัก", "ตัวเลขสรุปสำคัญบนหน้าแรก"),
    ("KQL / SPL / Sigma", "ภาษาค้นหาของ Sentinel / Splunk / รูปแบบกฎกลาง", "รูปแบบ query ที่ส่งออกไปใช้ใน SIEM อื่น"),
    ("Lateral movement", "การเคลื่อนที่ภายในเครือข่าย", "ผู้โจมตีขยายจากเครื่องหนึ่งไปเครื่องอื่น (T1021)"),
    ("LLM", "โมเดลภาษาขนาดใหญ่", "โมเดล AI ที่ประมวลผลภาษา เช่น Claude"),
    ("Lookalike / Typosquatting", "โดเมนเลียนแบบ", "โดเมนที่สะกดคล้ายของจริงเพื่อหลอกผู้ใช้"),
    ("Malware", "มัลแวร์ / โปรแกรมประสงค์ร้าย", "ซอฟต์แวร์อันตราย"),
    ("Manual case", "เคสที่สร้างเอง", "case ที่ analyst สร้าง ไม่รวม alert อัตโนมัติ"),
    ("MCP (Model Context Protocol)", "โปรโตคอลเชื่อมเครื่องมือกับ AI", "มาตรฐานที่ให้ AI agent เรียกเครื่องมือภายนอก"),
    ("MFA fatigue", "การกดดันด้วยคำขอ MFA ซ้ำ", "ส่งคำขอยืนยันตัวตนรัวๆ จนผู้ใช้กดยอมรับ (T1621)"),
    ("Monitor mode", "โหมดเฝ้าดู", "เก็บ log อย่างเดียว ไม่สร้าง alert"),
    ("NDR (Network Detection and Response)", "การตรวจจับและตอบสนองระดับเครือข่าย", "ระบบเฝ้าระวังทราฟฟิกเครือข่าย"),
    ("Notebook", "สมุดบันทึกการสืบสวน", "เอกสาร Markdown ของทีม"),
    ("Notification rule", "กฎการแจ้งเตือน", "เงื่อนไขว่า incident แบบใดแจ้งใคร ผ่านช่องทางใด"),
    ("Observable", "ค่าที่สังเกตได้", "ค่าใน log เช่น IP หรือโดเมน ที่นำไปเทียบกับ IOC"),
    ("Occurrences", "จำนวนครั้งที่เกิด", "จำนวน alert ซ้ำในกลุ่มเดียวกัน"),
    ("Offensive AI", "AI เชิงรุก/โจมตี", "การใช้ AI agent เพื่อโจมตี"),
    ("OSINT", "ข่าวกรองจากแหล่งเปิด", "ข้อมูลที่หาได้จากแหล่งสาธารณะ"),
    ("Pending", "รอดำเนินการ", "alert/งาน ที่ยังไม่มีใครจัดการ"),
    ("Permission", "สิทธิ์", "สิทธิ์ทำการกระทำหนึ่งอย่าง เช่น cases.close"),
    ("Phishing", "ฟิชชิง / อีเมลหลอกลวง", "การหลอกให้เปิดไฟล์หรือกรอกข้อมูล (T1566)"),
    ("Pipe query", "คำค้นแบบต่อท่อ", "ภาษาค้นหาที่ใช้ | ต่อขั้นตอน"),
    ("Platform user (MSSP)", "ผู้ใช้ระดับแพลตฟอร์ม", "เจ้าหน้าที่ผู้ให้บริการที่สลับดูได้ทุก tenant"),
    ("Playbook", "คู่มือปฏิบัติ", "ขั้นตอนมาตรฐานในการรับมือเหตุการณ์"),
    ("Policy", "นโยบาย", "การตั้งค่าที่ควบคุมพฤติกรรมระบบ เช่น four-eyes"),
    ("Priority", "ลำดับความสำคัญ", "low / medium / high / critical ของ case"),
    ("Process tree", "แผนผังโปรเซส", "ลำดับโปรแกรมแม่-ลูกที่ถูกเรียก"),
    ("Prompt injection", "การฝังคำสั่งในข้อความให้ AI", "ข้อความแฝงที่ทำให้ AI ทำสิ่งที่ไม่ได้ตั้งใจ"),
    ("Pseudonymization", "การใช้นามแฝง", "แทนชื่อผู้ใช้/อีเมล/IP ภายในด้วยรหัสก่อนส่งให้ AI"),
    ("Publish", "เผยแพร่", "ทำให้ rule เวอร์ชันใหม่มีผลกับการตรวจจับ"),
    ("Quality score", "คะแนนคุณภาพของ rule", "สัดส่วน alert ที่ไม่ถูกปฏิเสธใน 7 วัน"),
    ("Query", "คำค้น", "คำสั่งค้นหาข้อมูล"),
    ("Ransomware", "มัลแวร์เรียกค่าไถ่", "เข้ารหัสไฟล์แล้วเรียกเงิน (T1486)"),
    ("Rate limit", "การจำกัดอัตรา", "จำนวนครั้งสูงสุดที่เรียกได้ต่อนาที"),
    ("RBAC", "การควบคุมสิทธิ์ตามบทบาท", "กำหนดสิทธิ์ผ่านบทบาท (role)"),
    ("RDAP / WHOIS", "ข้อมูลผู้ถือครองโดเมน/IP", "บริการสอบถามเจ้าของโดเมนหรือ IP"),
    ("Real data", "ข้อมูลจริง", "log จริงที่ส่งเข้ามา (ป้าย REAL)"),
    ("Reconnaissance (Recon)", "การสอดแนม", "การสำรวจเป้าหมายก่อนโจมตี"),
    ("Redaction", "การปิดบังข้อมูล", "ซ่อนข้อมูลส่วนบุคคลบางส่วน"),
    ("Reoccurred", "เกิดซ้ำ", "alert ที่ปิดแล้วเกิดขึ้นอีก"),
    ("Response", "การตอบสนอง", "การกระทำเพื่อหยุดหรือแก้ไขเหตุการณ์"),
    ("Retention", "ระยะเก็บข้อมูล", "จำนวนวันที่ระบบเก็บข้อมูลก่อนลบ"),
    ("Retire (agent)", "ปลดระวาง", "เลิกใช้งาน agent กิจกรรมหลังจากนั้นถูกบล็อก"),
    ("Revoke", "เพิกถอน", "ยกเลิกการใช้งาน IOC หรือ asset"),
    ("Role", "บทบาท", "ชุดสิทธิ์ เช่น viewer, analyst, lead, admin"),
    ("Rollback", "ย้อนเวอร์ชัน", "คืน rule เป็นเวอร์ชันก่อนหน้า"),
    ("Rotate (key/token)", "ออกกุญแจใหม่", "สร้าง key ใหม่ และยกเลิกของเดิมทันที"),
    ("RTP (Real-time protection)", "การป้องกันแบบเรียลไทม์", "การป้องกันของ antivirus/EDR บนเครื่อง"),
    ("Rule", "กฎ", "ดู Detection rule"),
    ("Scope (agent)", "ขอบเขตสิทธิ์ของเอเจนต์", "เครื่องมือที่ agent ได้รับอนุญาตให้ใช้"),
    ("Session", "เซสชัน", "ช่วงการทำงานต่อเนื่องหนึ่งครั้งของ agent"),
    ("Severity", "ความรุนแรง", "info / low / medium / high / critical"),
    ("Shadow AI", "AI ที่ไม่ได้ลงทะเบียน", "AI agent ที่ทำงานในองค์กรโดยไม่ได้รับอนุญาต (AGT-011)"),
    ("SIEM", "ระบบรวบรวมและวิเคราะห์ log ความปลอดภัย", "ระบบเช่น Sentinel, Splunk"),
    ("Sightings", "การพบเห็น", "จำนวนครั้งที่ IOC ปรากฏใน log/alert ของ tenant"),
    ("Simulated data", "ข้อมูลจำลอง", "ข้อมูลที่ระบบสร้างเพื่อ demo (tenant default)"),
    ("SOC (Security Operations Center)", "ศูนย์ปฏิบัติการความปลอดภัย", "ทีม/ระบบเฝ้าระวังภัยไซเบอร์"),
    ("SSE (Server-Sent Events)", "การส่งข้อมูลสดจากเซิร์ฟเวอร์", "เทคนิคที่ทำให้หน้าจออัปเดตแบบสด"),
    ("STIX 2.1", "มาตรฐานแลกเปลี่ยนข่าวกรองภัย", "รูปแบบไฟล์ CTI ที่ MISP/OpenCTI ใช้"),
    ("Suppressed", "ถูกระงับ", "alert ที่ไม่ถูกสร้างเพราะ rule ถูกปิด"),
    ("Tactic", "ยุทธวิธี", "เป้าหมายของผู้โจมตีในแต่ละขั้น เช่น Initial Access"),
    ("Tag", "ป้ายกำกับ", "คำสั้นๆ สำหรับจัดกลุ่ม case/asset/IOC"),
    ("Task", "งาน", "งานย่อยที่มอบหมายในทีม"),
    ("Technique", "เทคนิค", "วิธีการโจมตีใน MITRE ATT&CK เช่น T1059.001 PowerShell"),
    ("Telemetry", "ข้อมูลการทำงานของระบบ", "log และเหตุการณ์ที่ส่งเข้ามาวิเคราะห์"),
    ("Tenant", "ผู้เช่าระบบ / ลูกค้า", "องค์กรที่ข้อมูลแยกจากกันโดยสมบูรณ์"),
    ("Threat", "ภัยคุกคาม", "ผู้โจมตี มัลแวร์ หรือเครื่องมือที่ก่อภัย"),
    ("Threat landscape", "ภาพรวมภัยคุกคาม", "แนวโน้มภัยจาก CTI และ alert"),
    ("Threshold", "เกณฑ์", "จำนวนครั้งขั้นต่ำในช่วงเวลาก่อน rule จะทำงาน"),
    ("Timeline", "ไทม์ไลน์", "ลำดับเหตุการณ์ตามเวลา"),
    ("TLP (Traffic Light Protocol)", "ระดับการเผยแพร่ข้อมูล", "CLEAR เผยแพร่ได้ · GREEN ในชุมชน · AMBER ในองค์กร · RED เฉพาะผู้รับ"),
    ("Tool call", "การเรียกใช้เครื่องมือ", "การที่ AI agent สั่งงานเครื่องมือ"),
    ("Triage", "การคัดกรอง", "การจัดลำดับและคัดแยก alert"),
    ("True positive", "ภัยจริง", "verdict: alert ถูกต้อง เป็นการโจมตีจริง"),
    ("Two-person rule", "กฎสองคน", "ดู Four-eyes principle"),
    ("Undetermined", "ยังสรุปไม่ได้", "verdict เมื่อข้อมูลไม่พอ"),
    ("Threat Map", "แผนที่ภัยคุกคาม", "ลูกโลกแสดงประเทศที่ตั้งโครงสร้างพื้นฐานเบื้องหลัง alert — ไม่ใช่ตัวตนผู้โจมตี"),
    ("Urgency", "ความเร่งด่วน", "คะแนน 0–100 ใช้เรียงลำดับ alert"),
    ("User-agent", "ข้อมูลระบุโปรแกรมผู้เรียก", "ข้อความระบุเบราว์เซอร์/เครื่องมือในคำขอ HTTP"),
    ("Verdict", "ผลวินิจฉัย", "True positive / False positive / Benign / ยังสรุปไม่ได้"),
    ("VirusTotal", "บริการตรวจชื่อเสียงไฟล์/URL", "บริการของ Google ที่รวมผล antivirus และ blocklist กว่า 70 ราย ระบบใช้ API v3 แบบค้นอย่างเดียว"),
    ("Reputation (VirusTotal)", "คะแนนชื่อเสียง", "คะแนนจากการโหวตของชุมชน VirusTotal ค่าติดลบ = ถูกมองว่าอันตราย"),
    ("Version", "เวอร์ชัน", "ฉบับของ rule แต่ละครั้งที่เผยแพร่"),
    ("Warning event", "เหตุการณ์ที่มีข้อสังเกต", "record ที่เวลาผิด/หาย หรือระบุเครื่อง/ผู้ใช้ไม่ได้"),
    ("Webhook", "เว็บฮุก", "URL ที่ระบบส่งข้อมูลไปให้ระบบอื่นอัตโนมัติ"),
    ("Workspace", "พื้นที่ทำงาน", "การตั้งค่าและข้อมูลขององค์กรใน tenant"),
    ("XDR (Extended Detection and Response)", "การตรวจจับและตอบสนองแบบขยาย", "เชื่อมข้อมูลหลายโดเมน (endpoint, email, identity, network, cloud)"),
]


def glossary() -> str:
    rows = sorted(GLOSSARY, key=lambda r: r[0].lower())
    out, letter = [], None
    for term, th, desc in rows:
        first = term[0].upper()
        if first != letter:
            letter = first
            out.append(f"\n**{letter}**\n\n| คำศัพท์ | คำแปล | ความหมายในระบบนี้ |\n|---|---|---|")
        out.append(f"| {term} | {th} | {desc} |")
    return f"รวม {len(rows)} คำ เรียงตามตัวอักษร\n" + "\n".join(out)


def permissions() -> str:
    from app import rbac
    roles = list(rbac.ROLES)
    head = "| สิทธิ์ | กลุ่ม | ใช้ทำอะไร | " + " | ".join(f"{rbac.ROLE_TH[r]} ({r})" for r in roles) + " |"
    sep = "|---|---|---|" + "---|" * len(roles)
    lines = [f"ทั้งหมด {len(rbac.PERMISSIONS)} สิทธิ์ · ✓ = บทบาทนั้นมีสิทธิ์นี้\n", head, sep]
    for pid, (grp, desc) in rbac.PERMISSIONS.items():
        lines.append(f"| `{pid}` | {grp} | {desc} | " + " | ".join("✓" if pid in rbac.ROLES[r] else "" for r in roles) + " |")
    lines.append("\n**คำอธิบายบทบาท**\n")
    lines += [f"- **{rbac.ROLE_TH[r]} (`{r}`)** — {rbac.ROLE_DESC[r]}" for r in roles]
    return "\n".join(lines)


def rules() -> str:
    from app import agent_detect, catalog, intel, offensive_ai
    lines = ["| Rule | ชื่อ | ความรุนแรง | Technique | Tactic | log ที่ต้องใช้ |", "|---|---|---|---|---|---|"]
    for src in (offensive_ai.RULES, agent_detect.RULES, intel.IOC_RULES):
        for rid, (title, sev, tech, tactic) in src.items():
            logs = ", ".join(catalog.RULE_SOURCES.get(rid, ["AI agent audit"]))
            lines.append(f"| {rid} | {title} | {sev} | {tech} | {tactic} | {logs} |")
    lines.append("\nนอกจากนี้ยังมี custom rule (CUS-xxx) ที่แต่ละ tenant สร้างเองใน AI Rule Assistant "
                 "และสัญญาณ EDR/XDR พื้นฐานของเครื่องจำลอง (เฉพาะ tenant default)")
    return "\n".join(lines)


def api() -> str:
    src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    lines = ["ทุก endpoint ส่ง token ใน header `X-API-Key` (และ `X-Tenant` สำหรับผู้ใช้ระดับแพลตฟอร์ม) · "
             "คอลัมน์ \"สิทธิ์\" คือสิทธิ์ขั้นต่ำในการเรียก บาง endpoint ตรวจสิทธิ์เพิ่มตามการกระทำจริง เช่น "
             "`PATCH /api/soc/incidents/{id}` (cases.update / cases.assign / cases.close), "
             "`POST /api/soc/alerts/action` (alerts.acknowledge / assign / escalate / close), "
             "`PATCH /api/users/{username}` (users.manage / roles.manage) และการส่งออก CSV (soc.export)\n",
             "| Method | Path | สิทธิ์ | คำอธิบาย (จาก docstring) |", "|---|---|---|---|"]
    pat = re.compile(r'@app\.(get|post|put|patch|delete)\("([^"]+)"[^\n]*\n((?:(?!@app\.).*\n){1,10})')
    for m in pat.finditer(src):
        method, path, body = m.group(1).upper(), m.group(2), m.group(3)
        perm = re.search(r'require\("([^"]+)"\)', body)
        doc = re.search(r'"""(.+?)(?:"""|\n)', body)
        desc = doc.group(1).strip().rstrip(".") if doc else ""
        p = f"`{perm.group(1)}`" if perm else ("intake key" if path == "/api/soc/intake" else
                                                "feed key ใน URL" if path.startswith("/feeds/") else "ไม่ต้องยืนยันตัว / token ใดก็ได้")
        lines.append(f"| {method} | `{path}` | {p} | {desc.replace('|', '/')} |")
    return "\n".join(lines)


ENV_TH = {
    "ANTHROPIC_API_KEY": "กุญแจ Claude API เปิดใช้ฟีเจอร์ AI",
    "ANTHROPIC_AUTH_TOKEN": "ทางเลือกแทน ANTHROPIC_API_KEY",
    "HIBP_API_KEY": "กุญแจ Have I Been Pwned (OSINT Email)",
    "IPINFO_TOKEN": "กุญแจ ipinfo.io (OSINT IP)",
    "VT_API_KEY": "กุญแจ VirusTotal API v3 (ค้นชื่อเสียง hash/URL/domain/IP)",
    "VT_RATE_PER_MIN": "จำนวนครั้งต่อนาทีที่เรียก VirusTotal ได้ (บัญชีฟรี 4)",
    "VT_DAILY_QUOTA": "จำนวนครั้งต่อวันที่เรียก VirusTotal ได้ (บัญชีฟรี 500, นับตามวัน UTC)",
    "VT_CACHE_TTL": "เก็บผล VirusTotal ใน cache กี่วินาที (ค่าเริ่ม 3600)",
    "VT_BLOCK_DOMAINS": "โดเมนภายในเพิ่มเติมที่ห้ามส่งไป VirusTotal (คั่นด้วย ,)",
    "OSINT_API_KEY": "break-glass admin key",
    "OSINT_DB_PATH": "ที่อยู่ไฟล์ฐานข้อมูล SQLite (บน Render ใช้ /var/data/osint.db)",
    "OSINT_HTTP_TIMEOUT": "timeout (วินาที) ของการเรียกภายนอกใน OSINT",
    "OSINT_RATE_LIMIT": "จำนวนครั้งต่อนาทีต่อ IP สำหรับการเขียน/สแกน",
    "OSINT_READ_RATE_LIMIT": "จำนวนครั้งต่อนาทีต่อ IP สำหรับการอ่าน",
    "OSINT_RETENTION_DAYS": "ระยะเก็บผลสแกน OSINT และ audit (วัน)",
    "OSINT_USER_AGENT": "User-Agent ที่ใช้ตอนสแกน",
    "SOC_AI_EFFORT": "ระดับความละเอียดของ AI (low/medium/high/xhigh/max)",
    "SOC_AI_MODEL": "โมเดล Claude ที่ใช้",
    "SOC_AI_REDACT": "ใช้นามแฝงแทนข้อมูลส่วนบุคคลก่อนส่งให้ AI (on/off)",
    "SOC_AUTOSTART": "เริ่มดึง CTI และเครื่องจำลองทันทีที่ระบบเปิด",
    "SOC_BACKUP_DIR": "โฟลเดอร์เก็บ backup อัตโนมัติ",
    "SOC_BACKUP_HOURS": "ความถี่การ backup (ชั่วโมง)",
    "SOC_BACKUP_KEEP": "จำนวน backup ที่เก็บไว้",
    "SOC_NOTIFY_DEBOUNCE": "หน่วงการแจ้งเตือน (วินาที) เพื่อรวมการเปลี่ยนแปลง",
    "SOC_NOTIFY_EMAIL_TO": "อีเมลผู้รับแจ้งเตือน (คั่นด้วย ,)",
    "SOC_NOTIFY_LINE_TO": "ID กลุ่ม/ผู้ใช้ LINE ที่รับแจ้งเตือน",
    "SOC_NOTIFY_LINE_TOKEN": "channel access token ของ LINE Messaging API",
    "SOC_NOTIFY_MIN_SEVERITY": "ความรุนแรงขั้นต่ำที่แจ้งเตือนอัตโนมัติ",
    "SOC_NOTIFY_REDACT": "ปิดบังชื่อผู้ใช้ในข้อความแจ้งเตือน",
    "SOC_NOTIFY_SIMULATED": "แจ้งเตือนข้อมูลจำลองด้วยหรือไม่",
    "SOC_NOTIFY_SLACK_URL": "Slack incoming webhook URL",
    "SOC_NOTIFY_TEAMS_URL": "Microsoft Teams webhook URL",
    "SOC_NOTIFY_WEBHOOK_URL": "webhook ทั่วไป (SOAR/ticketing)",
    "SOC_NOTIFY_MAX_PER_10MIN": "เพดานจำนวนข้อความแจ้งเตือนต่อ 10 นาที",
    "SOC_PUBLIC_URL": "URL สาธารณะของระบบ (ใช้ในลิงก์แจ้งเตือนและ feed URL)",
    "SOC_RAW_RETENTION_DAYS": "ระยะเก็บ log ดิบ (วัน)",
    "SOC_RETENTION_DAYS": "ระยะเก็บข้อมูล SOC (วัน)",
    "SOC_HOME_COUNTRY": "ประเทศของเรา (ISO 2 ตัว) ที่ Threat Map ลากเส้นเข้าหา (ค่าเริ่ม TH)",
    "SOC_SCALE": "ตัวคูณขนาดข้อมูลจำลองและความจุ (1–20)",
    "SOC_SIMULATION": "เปิดเครื่องจำลองข้อมูลใน tenant default",
    "SMTP_HOST": "เซิร์ฟเวอร์อีเมลสำหรับแจ้งเตือน", "SMTP_PORT": "พอร์ต SMTP (ค่าเริ่ม 587)",
    "SMTP_USER": "ผู้ใช้ SMTP", "SMTP_PASSWORD": "รหัสผ่าน SMTP", "SMTP_FROM": "อีเมลผู้ส่ง",
}
SECRET = {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "HIBP_API_KEY", "IPINFO_TOKEN", "VT_API_KEY", "OSINT_API_KEY",
          "SOC_NOTIFY_LINE_TOKEN", "SMTP_PASSWORD", "SOC_NOTIFY_TEAMS_URL", "SOC_NOTIFY_SLACK_URL", "SOC_NOTIFY_WEBHOOK_URL"}


def env() -> str:
    found: dict[str, str] = {}
    for f in (ROOT / "app").rglob("*.py"):
        for m in re.finditer(r'(?:getenv|_env)\("([A-Z0-9_]+)"(?:,\s*"([^"]*)")?', f.read_text(encoding="utf-8")):
            found.setdefault(m.group(1), m.group(2) if m.group(2) is not None else "")
    for k in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM"):
        found.setdefault(k, "587" if k == "SMTP_PORT" else "")
    lines = ["| ตัวแปร | ค่าเริ่มต้น | ความหมาย | ความลับ |", "|---|---|---|---|"]
    for k in sorted(found):
        lines.append(f"| `{k}` | {('`' + found[k] + '`') if found[k] else '—'} | {ENV_TH.get(k, '')} | {'🔒 ตั้งใน Render Environment เท่านั้น' if k in SECRET else ''} |")
    return "\n".join(lines)


SECTIONS = {"glossary": glossary, "permissions": permissions, "rules": rules, "api": api, "env": env}


def render(text: str) -> str:
    for name, fn in SECTIONS.items():
        pat = re.compile(rf"(<!-- BEGIN GENERATED:{name} -->\n).*?(<!-- END GENERATED:{name} -->)", re.S)
        text = pat.sub(lambda m: m.group(1) + fn() + "\n" + m.group(2), text)
    return text


def main() -> int:
    cur = MANUAL.read_text(encoding="utf-8")
    new = render(cur)
    if "--check" in sys.argv:
        if new != cur:
            print("docs/USER_MANUAL.md is out of date — run: python tools/gen_manual.py")
            return 1
        return 0
    MANUAL.write_text(new, encoding="utf-8")
    print(f"updated {MANUAL.relative_to(ROOT)} ({len(new.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
