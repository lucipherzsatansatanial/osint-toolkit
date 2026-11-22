"""Role-based access control: named users with personal API tokens.

- Each person / log shipper gets their own token (shown once; only a SHA-256 hash is stored).
- The audit log records the authenticated user, not a name typed into a form.
- OSINT_API_KEY still works as a break-glass admin key (e.g. to create the first users).
- With no OSINT_API_KEY and no users the app runs open (local development only).

Roles
  viewer   read dashboards, incidents, reports, hunting
  analyst  + OSINT scans and scan history, incident workflow, AI copilot
  lead     + ingest, register agents, containment, alert-channel tests, enable custom rules
  admin    + user management
  ingest   service account for log shippers: ingest only
"""
import hashlib
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field

from app.config import settings

_lock = threading.Lock()

READ = {"soc.read"}
ANALYST = READ | {"osint.scan", "osint.history", "incident.write", "ai.use"}
LEAD = ANALYST | {"ingest", "agents.manage", "respond", "notify.test", "rules.manage"}
ROLES: dict[str, set[str]] = {
    "viewer": READ,
    "analyst": ANALYST,
    "lead": LEAD,
    "admin": LEAD | {"users.manage"},
    "ingest": {"ingest"},
}
ROLE_TH = {"viewer": "ผู้ดู", "analyst": "นักวิเคราะห์", "lead": "หัวหน้าทีม SOC", "admin": "ผู้ดูแลระบบ",
           "ingest": "บัญชีส่ง log"}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")
PLATFORM = "*"  # users of this tenant are platform (MSSP) staff and may act in any tenant via X-Tenant

SCHEMA = """
CREATE TABLE IF NOT EXISTS soc_users (
    username TEXT PRIMARY KEY, role TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    disabled INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, created_by TEXT, last_seen REAL
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
    return Principal(row["username"], row["role"], ip, True, set(ROLES.get(row["role"], set())),
                     "default" if platform else row["tenant"], platform)


def create_user(username: str, role: str, created_by: str, tenant: str = "default") -> str:
    if not USERNAME_RE.match(username):
        raise ValueError("username: 2-63 chars, lowercase letters, digits, . _ -")
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
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
    if role is not None and role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
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
