"""Integrations catalog: what this platform can actually connect to, and whether it is configured right now.
Status is computed from the server's environment and stored state — nothing here is a marketplace claim."""

CATEGORIES = ("Endpoint", "Network", "Identity", "Cloud Providers", "Generic", "Threat Intelligence", "Collaboration Tools",
              "Email", "AI")
CONTENT_TYPES = {"intake": "Intake formats", "feed_in": "CTI feeds (in)", "feed_out": "Feeds (out)",
                 "notify": "Notification channels", "enrich": "Enrichment", "ai": "AI", "export": "Detection exports"}

# id, name, category, content type, description, how to set up
CATALOG = [
    ("native", "Native JSON / NDJSON", "Generic", "intake", "รูปแบบกลางของระบบ: process, http, net, logon, db, dlp และ AI-agent audit",
     "สร้าง Intake แบบ native แล้วส่ง NDJSON ไปที่ POST /api/soc/intake"),
    ("ecs", "Elastic Common Schema (Beats / Elastic Agent)", "Generic", "intake",
     "Winlogbeat, Packetbeat, Filebeat, Auditbeat และ log ที่แปลงเป็น ECS แล้ว (เช่นผ่าน Logstash / Fluent Bit)",
     "สร้าง Intake แบบ ecs; ตั้ง output http ของ Logstash/Fluent Bit ไปที่ /api/soc/intake พร้อม X-Intake-Key"),
    ("defender", "Microsoft Defender for Endpoint (Advanced Hunting)", "Endpoint", "intake",
     "DeviceProcessEvents / DeviceNetworkEvents / DeviceLogonEvents ที่ export จาก Advanced Hunting หรือ Streaming API",
     "สร้าง Intake แบบ defender แล้วส่งผลลัพธ์ JSON"),
    ("access_log", "Web server access log (Apache / Nginx combined)", "Network", "intake",
     "ตรวจ recon burst, rotating proxy, user-agent ของเครื่องมือโจมตี AI", "สร้าง Intake แบบ access_log; ระบุ host ด้วย ?host="),
    ("ship_logs", "tools/ship_logs.py (log shipper)", "Generic", "intake", "สคริปต์ส่งไฟล์ log เป็นชุด พร้อม retry",
     "python tools/ship_logs.py --url <server>/api/soc/intake ... (ดู README)"),
    ("threatfox", "abuse.ch ThreatFox", "Threat Intelligence", "feed_in", "IOC ล่าสุด (IP:port, domain, URL, hash) พร้อมชื่อ malware",
     "เปิดใช้อัตโนมัติ — ต้องให้เซิร์ฟเวอร์ออก internet ไป threatfox.abuse.ch ได้"),
    ("feodo", "abuse.ch Feodo Tracker", "Threat Intelligence", "feed_in", "botnet C2 IP", "เปิดใช้อัตโนมัติ"),
    ("kev", "CISA Known Exploited Vulnerabilities", "Threat Intelligence", "feed_in", "CVE ที่ถูกใช้โจมตีจริง", "เปิดใช้อัตโนมัติ"),
    ("agentic", "ThreatDefence agentic-attack-detections (MIT)", "Threat Intelligence", "feed_in",
     "indicator ของ framework โจมตีด้วย AI agent", "เปิดใช้อัตโนมัติ"),
    ("stix_out", "STIX 2.1 / TAXII-style pull feed", "Threat Intelligence", "feed_out",
     "ส่ง IOC ออกเป็น STIX 2.1 bundle ให้ CTI platform อื่น (MISP, OpenCTI ฯลฯ ดึงผ่าน URL)", "สร้าง Feed แบบ stix"),
    ("ebl_out", "Firewall external block list (FortiGate / Palo Alto EDL / pfSense)", "Network", "feed_out",
     "รายการ IP/domain/URL แบบข้อความบรรทัดละรายการ ให้ไฟร์วอลล์ดึงไปบล็อก", "สร้าง Feed แบบ text แล้วใส่ URL ในไฟร์วอลล์"),
    ("teams", "Microsoft Teams", "Collaboration Tools", "notify", "Adaptive Card เมื่อมี incident", "ตั้ง SOC_NOTIFY_TEAMS_URL"),
    ("line", "LINE Messaging API", "Collaboration Tools", "notify", "push message ไปกลุ่ม/ผู้ใช้", "ตั้ง SOC_NOTIFY_LINE_TOKEN และ SOC_NOTIFY_LINE_TO"),
    ("slack", "Slack", "Collaboration Tools", "notify", "incoming webhook", "ตั้ง SOC_NOTIFY_SLACK_URL"),
    ("webhook", "Generic webhook (SOAR / ticketing)", "Generic", "notify", "POST JSON ของ incident ไปยังระบบอื่น", "ตั้ง SOC_NOTIFY_WEBHOOK_URL"),
    ("email", "Email (SMTP)", "Email", "notify", "อีเมลแจ้ง incident", "ตั้ง SMTP_HOST, SMTP_FROM, SOC_NOTIFY_EMAIL_TO"),
    ("claude", "Anthropic Claude", "AI", "ai", "AI SOC Copilot, NL hunting, rule assistant (pseudonymise ก่อนส่ง)", "ตั้ง ANTHROPIC_API_KEY"),
    ("hibp", "Have I Been Pwned", "Identity", "enrich", "ตรวจอีเมลรั่วใน OSINT Toolkit", "ตั้ง HIBP_API_KEY"),
    ("ipinfo", "ipinfo.io", "Network", "enrich", "ข้อมูล ASN/ประเทศของ IP", "ตั้ง IPINFO_TOKEN (ไม่ตั้งก็ใช้ได้แบบจำกัด)"),
    ("kql", "Microsoft Sentinel / Defender (KQL)", "Endpoint", "export", "hunting query ของ offensive-AI rules", "ไฟล์ใน detections/offensive_ai/*.kql"),
    ("spl", "Splunk (SPL)", "Generic", "export", "hunting search ของ offensive-AI rules", "ไฟล์ใน detections/offensive_ai/*.spl"),
    ("sigma", "Sigma", "Generic", "export", "rule กลางแปลงไปได้หลาย SIEM", "ไฟล์ใน detections/offensive_ai/*.yml"),
]


def catalog(state: dict) -> list[dict]:
    """state: notify_channels, ai_enabled, hibp, ipinfo, feeds_ok {name: bool}, intakes {format: n}, feeds_out {fmt: n}."""
    out = []
    for iid, name, cat, ctype, desc, how in CATALOG:
        if ctype == "notify":
            status = "configured" if iid in state["notify_channels"] else "available"
        elif ctype == "feed_in":
            ok = state["feeds_ok"].get(iid)
            status = "active" if ok else "error" if ok is False else "available"
        elif ctype == "intake":
            n = state["intakes"].get(iid, 0)
            status = "configured" if n else "available"
        elif ctype == "feed_out":
            n = state["feeds_out"].get("stix" if iid == "stix_out" else "text", 0)
            status = "configured" if n else "available"
        elif iid == "claude":
            status = "configured" if state["ai_enabled"] else "available"
        elif iid in ("hibp", "ipinfo"):
            status = "configured" if state[iid] else "available"
        else:
            status = "built_in"
        out.append({"id": iid, "name": name, "category": cat, "content_type": ctype,
                    "content_type_name": CONTENT_TYPES[ctype], "description": desc, "setup": how, "status": status,
                    "count": state["intakes"].get(iid) if ctype == "intake" else None})
    return out
