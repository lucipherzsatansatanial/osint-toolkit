"""Role-based access control: named users with personal API tokens and per-action permissions.

- Each person / log shipper gets their own token (shown once; only a SHA-256 hash is stored).
- The audit log records the authenticated user, not a name typed into a form.
- OSINT_API_KEY still works as a break-glass admin key (e.g. to create the first users).
- With no OSINT_API_KEY and no users the app runs open (local development only).

Permissions are named after the action they allow (see PERMISSIONS). Built-in roles bundle them; each tenant can
also define custom roles, but nobody can create or assign a role holding a permission they do not hold themselves.
Two actions are additionally separated at run time (see app.main): response actions need a second person
(respond.execute requests, respond.approve approves), and agent permission changes need agents.approve by someone
other than the proposer.
"""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field

from app.config import settings

_lock = threading.Lock()

# id -> (group, Thai description). Order defines the order in the UI.
PERMISSIONS: dict[str, tuple[str, str]] = {
    "soc.read": ("ข้อมูล SOC", "เปิด dashboard หน้าแรก, live stream, งาน (Tasks) และการแจ้งเตือนของตัวเอง"),
    "alerts.read": ("ข้อมูล SOC", "ดูรายการ alert, Offensive AI และ Threat Landscape"),
    "events.read": ("ข้อมูล SOC", "ดู log ดิบ (Events) และ log ที่เกี่ยวกับ case"),
    "cases.read": ("ข้อมูล SOC", "ดู case/incident, timeline, แผนตอบสนอง, attack chains"),
    "assets.read": ("ข้อมูล SOC", "ดู asset, ระดับความสำคัญ และ endpoint"),
    "entities.read": ("ข้อมูล SOC", "ดู entity และ intake (แหล่ง log)"),
    "query.run": ("ค้นหาและวิเคราะห์", "รัน query builder / hunting / ขยาย graph และบันทึก query"),
    "notebooks.read": ("ค้นหาและวิเคราะห์", "อ่าน notebook และ graph ที่บันทึกไว้"),
    "notebooks.write": ("ค้นหาและวิเคราะห์", "สร้าง/แก้ notebook และ graph"),
    "soc.export": ("ค้นหาและวิเคราะห์", "ส่งออกข้อมูล SOC (CSV ของ incident, รายงาน incident, รายงาน IOC)"),
    "cases.create": ("จัดการเคส", "สร้าง case ด้วยมือ"),
    "cases.update": ("จัดการเคส", "แก้ case (บันทึก, priority, tag, verdict, custom fields, งาน, ขั้นตอนตอบสนอง) และรับงานเอง"),
    "cases.assign": ("จัดการเคส", "มอบหมาย case/งานให้ผู้อื่น"),
    "cases.close": ("จัดการเคส", "ปิด case (resolved / false positive / closed) หรือเปิดใหม่"),
    "alerts.acknowledge": ("จัดการ Alert", "รับทราบ alert"),
    "alerts.assign": ("จัดการ Alert", "มอบหมาย alert ให้ผู้อื่น"),
    "alerts.escalate": ("จัดการ Alert", "ยกระดับ alert เป็น case / เพิ่ม priority ของ case"),
    "alerts.close": ("จัดการ Alert", "ปิด alert พร้อมเหตุผล"),
    "threatintel.read": ("Threat Intelligence / OSINT", "ค้น Intelligence, IOC collections, feeds ที่ส่งออก"),
    "threatintel.curate": ("Threat Intelligence / OSINT", "เพิ่ม/แก้/revoke IOC, collection และ feed ส่งออก"),
    "threatintel.enrich": ("Threat Intelligence / OSINT", "ค้นชื่อเสียง IOC กับบริการภายนอก เช่น VirusTotal (ใช้โควตา API)"),
    "osint.scan": ("Threat Intelligence / OSINT", "สแกน OSINT"),
    "osint.history": ("Threat Intelligence / OSINT", "ดูประวัติการสแกน OSINT"),
    "osint.export": ("Threat Intelligence / OSINT", "ส่งออกประวัติการสแกน OSINT (CSV)"),
    "rules.read": ("กฎและการตรวจจับ", "ดู rules catalog และ custom rules"),
    "rules.edit": ("กฎและการตรวจจับ", "ร่าง/ทดสอบ/บันทึก custom rule (ยังไม่มีผลจนกว่าจะเผยแพร่)"),
    "rules.publish": ("กฎและการตรวจจับ", "เผยแพร่/ปิด rule (มีผลกับการตรวจจับทันที)"),
    "rules.rollback": ("กฎและการตรวจจับ", "ย้อน rule กลับไปเวอร์ชันก่อนหน้า"),
    "agents.read": ("Agentic AI", "ดู AI agent inventory, session, risk และ hunting ใน agent audit log"),
    "agents.edit": ("Agentic AI", "เสนอเพิ่ม/แก้สิทธิ์ของ agent (รออนุมัติ)"),
    "agents.approve": ("Agentic AI", "อนุมัติ/ปฏิเสธคำขอแก้สิทธิ์ agent (ผู้อนุมัติต้องไม่ใช่ผู้เสนอ)"),
    "agents.deploy": ("Agentic AI", "นำ agent เข้าใช้งาน / ปลดออก (retire)"),
    "ai.copilot": ("AI", "ใช้ AI SOC Copilot / SOC Assistant / สรุป attack chain"),
    "ai.hunt": ("AI", "ค้นด้วยภาษาธรรมชาติ (AI hunting)"),
    "ai.enrich": ("AI", "enrich indicator ด้วย AI"),
    "offensive.read": ("AI", "ดูหน้า Offensive AI: framework โจมตีด้วย AI, detection และ hunting query (ข้อมูลเทคนิคผู้โจมตี)"),
    "respond.execute": ("การตอบสนอง", "ขอปฏิบัติการตอบสนอง เช่น กักกัน/ปล่อย AI agent"),
    "respond.approve": ("การตอบสนอง", "อนุมัติการตอบสนองที่ผู้อื่นขอ"),
    "assets.manage": ("ระบบและการกำกับดูแล", "เพิ่ม asset, แก้ tag และระดับความสำคัญ, revoke asset"),
    "integrations.manage": ("ระบบและการกำกับดูแล", "จัดการกฎแจ้งเตือนและทดสอบช่องทางแจ้งเตือน"),
    "ingest.sources.manage": ("ระบบและการกำกับดูแล", "จัดการ intake (key) และ entity"),
    "ingest.submit": ("ระบบและการกำกับดูแล", "ส่ง log เข้า /api/soc/ingest (บัญชีเครื่อง)"),
    "governance.read": ("ระบบและการกำกับดูแล", "ดูการใช้ AI/ค่าใช้จ่าย และนโยบายกำกับดูแล"),
    "governance.manage": ("ระบบและการกำกับดูแล", "แก้ข้อมูลองค์กร, นโยบาย, custom fields, case templates, สำรองข้อมูล"),
    "users.read": ("ผู้ใช้และการตรวจสอบ", "ดูรายชื่อผู้ใช้และบทบาท"),
    "users.manage": ("ผู้ใช้และการตรวจสอบ", "สร้างผู้ใช้ และระงับ/เปิดใช้บัญชี"),
    "roles.manage": ("ผู้ใช้และการตรวจสอบ", "สร้าง/แก้บทบาท และเปลี่ยนบทบาทผู้ใช้"),
    "tokens.manage": ("ผู้ใช้และการตรวจสอบ", "ออก token ใหม่ให้ผู้ใช้ (rotate)"),
    "audit.read": ("ผู้ใช้และการตรวจสอบ", "อ่าน/ส่งออก/ตรวจความครบถ้วนของ audit log"),
}
ALL = set(PERMISSIONS)

READ = {"soc.read", "alerts.read", "events.read", "cases.read", "assets.read", "entities.read", "threatintel.read",
        "rules.read", "agents.read", "notebooks.read"}
ANALYST = READ | {"query.run", "notebooks.write", "soc.export", "cases.create", "cases.update", "cases.close",
                  "alerts.acknowledge", "alerts.escalate", "alerts.close", "threatintel.curate", "threatintel.enrich", "osint.scan",
                  "osint.history", "rules.edit", "agents.edit", "ai.copilot", "ai.hunt", "ai.enrich",
                  "offensive.read"}
LEAD = ANALYST | {"cases.assign", "alerts.assign", "rules.publish", "rules.rollback", "agents.approve", "agents.deploy",
                  "respond.execute", "respond.approve", "osint.export", "assets.manage", "governance.read",
                  "audit.read", "users.read"}
ROLES: dict[str, set[str]] = {
    "viewer": READ,
    "analyst": ANALYST,
    "lead": LEAD,
    "admin": ALL - {"ingest.submit"},
    "ingest": {"ingest.submit"},
}
ROLE_TH = {"viewer": "ผู้ดู", "analyst": "นักวิเคราะห์", "lead": "หัวหน้าทีม SOC", "admin": "ผู้ดูแลระบบ",
           "ingest": "บัญชีส่ง log"}
ROLE_DESC = {
    "viewer": "อ่านข้อมูลที่จำเป็นอย่างเดียว ไม่มีสิทธิ์ส่งออก",
    "analyst": "ค้นหา วิเคราะห์ จัดการ case/alert ของตัวเอง — ไม่มี respond.execute, rules.publish, agents.deploy",
    "lead": "+ มอบหมายงาน เผยแพร่/ย้อน rule อนุมัติการตอบสนองและสิทธิ์ agent (อนุมัติงานของตัวเองไม่ได้)",
    "admin": "จัดการผู้ใช้ บทบาท token การเชื่อมต่อ แหล่ง log และนโยบาย พร้อม audit.read",
    "ingest": "บัญชีเครื่องสำหรับส่ง log เท่านั้น ไม่มีสิทธิ์อ่านข้อมูล SOC",
}
CUSTOM_ROLE_RE = re.compile(r"^[a-z][a-z0-9_-]{1,30}$")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")
PLATFORM = "*"  # users of this tenant are platform (MSSP) staff and may act in any tenant via X-Tenant

SCHEMA = """
CREATE TABLE IF NOT EXISTS soc_users (
    username TEXT PRIMARY KEY, role TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    disabled INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, created_by TEXT, last_seen REAL
);
CREATE TABLE IF NOT EXISTS soc_roles (
    tenant TEXT NOT NULL, name TEXT NOT NULL, label TEXT, perms TEXT NOT NULL, created_by TEXT, updated_at REAL,
    PRIMARY KEY (tenant, name)
);
"""


@dataclass
class Principal:
    name: str
    role: str
    ip: str = "unknown"
    named: bool = True  # False for the bootstrap key / open dev mode (no personal identity)
    perms: set[str] = field(default_factory=set)
    tenant: str = "default"     # tenant this request acts in
    platform: bool = False      # may choose the tenant (MSSP staff / bootstrap key)

    def can(self, perm: str) -> bool:
        return perm in self.perms


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(settings.db_path) or ".", exist_ok=True)
    c = sqlite3.connect(settings.db_path)
    c.row_factory = sqlite3.Row
    return c


def init() -> None:
    with _lock, _conn() as c:
        c.executescript(SCHEMA)
        cols = {r["name"] for r in c.execute("PRAGMA table_info(soc_users)")}
        if "tenant" not in cols:  # migrate single-tenant installs
            c.execute("ALTER TABLE soc_users ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default'")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return "soc_" + secrets.token_urlsafe(32)


def has_users() -> bool:
    with _lock, _conn() as c:
        return c.execute("SELECT 1 FROM soc_users LIMIT 1").fetchone() is not None


def authenticate(token: str, ip: str) -> Principal | None:
    if not token:
        return None
    with _lock, _conn() as c:
        row = c.execute("SELECT username, role, disabled, last_seen, tenant FROM soc_users WHERE token_hash = ?",
                        (_hash(token),)).fetchone()
        if row is None or row["disabled"]:
            return None
        if not row["last_seen"] or time.time() - row["last_seen"] > 60:  # avoid a write per request
            c.execute("UPDATE soc_users SET last_seen = ? WHERE username = ?", (time.time(), row["username"]))
    platform = row["tenant"] == PLATFORM
    return Principal(row["username"], row["role"], ip, True, role_perms(row["role"], row["tenant"]),
                     "default" if platform else row["tenant"], platform)


# ---------- roles ----------
def custom_roles(tenant: str) -> dict[str, dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT name, label, perms, created_by, updated_at FROM soc_roles WHERE tenant = ?", (tenant,)).fetchall()
    return {r["name"]: {"name": r["name"], "label": r["label"] or r["name"], "perms": sorted(set(json.loads(r["perms"])) & ALL),
                        "created_by": r["created_by"], "updated_at": r["updated_at"], "custom": True} for r in rows}


def role_perms(role: str, tenant: str) -> set[str]:
    if role in ROLES:
        return set(ROLES[role])
    cr = custom_roles(tenant).get(role)
    return set(cr["perms"]) if cr else set()


def role_exists(role: str, tenant: str) -> bool:
    return role in ROLES or role in custom_roles(tenant)


def save_role(tenant: str, name: str, label: str, perms: set[str], by: str) -> dict:
    if not CUSTOM_ROLE_RE.match(name) or name in ROLES:
        raise ValueError("role name: 2-31 chars a-z 0-9 _ - and not a built-in role name")
    unknown = perms - ALL
    if unknown:
        raise ValueError(f"unknown permissions: {', '.join(sorted(unknown))}")
    if "ingest.submit" in perms and perms != {"ingest.submit"}:
        raise ValueError("ingest.submit is for machine accounts only and cannot be combined with other permissions")
    with _lock, _conn() as c:
        c.execute("INSERT OR REPLACE INTO soc_roles (tenant, name, label, perms, created_by, updated_at) VALUES (?,?,?,?,?,?)",
                  (tenant, name, label or name, json.dumps(sorted(perms)), by, time.time()))
    return custom_roles(tenant)[name]


def delete_role(tenant: str, name: str) -> bool:
    with _lock, _conn() as c:
        if c.execute("SELECT 1 FROM soc_users WHERE role = ? AND tenant = ? LIMIT 1", (name, tenant)).fetchone():
            raise ValueError("role is still assigned to users")
        return c.execute("DELETE FROM soc_roles WHERE tenant = ? AND name = ?", (tenant, name)).rowcount > 0


def all_roles(tenant: str) -> list[dict]:
    out = [{"name": r, "label": ROLE_TH[r], "description": ROLE_DESC[r], "perms": sorted(p), "custom": False}
           for r, p in ROLES.items()]
    return out + sorted(custom_roles(tenant).values(), key=lambda r: r["name"])


def create_user(username: str, role: str, created_by: str, tenant: str = "default") -> str:
    if not USERNAME_RE.match(username):
        raise ValueError("username: 2-63 chars, lowercase letters, digits, . _ -")
    if not role_exists(role, tenant):
        raise ValueError(f"unknown role '{role}'")
    if tenant != PLATFORM and not TENANT_RE.match(tenant):
        raise ValueError("tenant: 2-41 chars, lowercase letters, digits and -")
    token = new_token()
    with _lock, _conn() as c:
        try:
            c.execute("INSERT INTO soc_users (username, role, token_hash, created_at, created_by, tenant) VALUES (?,?,?,?,?,?)",
                      (username, role, _hash(token), time.time(), created_by, tenant))
        except sqlite3.IntegrityError as e:
            raise ValueError("username already exists") from e
    return token


def rotate(username: str) -> str | None:
    token = new_token()
    with _lock, _conn() as c:
        n = c.execute("UPDATE soc_users SET token_hash = ? WHERE username = ?", (_hash(token), username)).rowcount
    return token if n else None


def update(username: str, role: str | None = None, disabled: bool | None = None) -> bool:
    if role is not None and not role_exists(role, user_tenant(username) or "default"):
        raise ValueError(f"unknown role '{role}'")
    sets, args = [], []
    if role is not None:
        sets.append("role = ?")
        args.append(role)
    if disabled is not None:
        sets.append("disabled = ?")
        args.append(1 if disabled else 0)
    if not sets:
        return False
    with _lock, _conn() as c:
        return c.execute(f"UPDATE soc_users SET {', '.join(sets)} WHERE username = ?", (*args, username)).rowcount > 0


def list_users(tenant: str | None = None) -> list[dict]:
    q = "SELECT username, role, disabled, created_at, created_by, last_seen, tenant FROM soc_users"
    args: tuple = ()
    if tenant is not None:
        q += " WHERE tenant = ?"
        args = (tenant,)
    with _lock, _conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY tenant, username", args)]


def user_tenant(username: str) -> str | None:
    with _lock, _conn() as c:
        r = c.execute("SELECT tenant FROM soc_users WHERE username = ?", (username,)).fetchone()
    return r["tenant"] if r else None


def tenants() -> list[str]:
    with _lock, _conn() as c:
        return sorted({r["tenant"] for r in c.execute("SELECT DISTINCT tenant FROM soc_users")} - {PLATFORM})
