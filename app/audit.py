"""SQLite audit trail and case history.

Every scan records who ran it, against what, and why. Under Thailand's PDPA,
person-related lookups (email, username) need a documented purpose and lawful
basis; this log is the evidence of that.
"""
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from app.config import settings

_lock = threading.Lock()
RETENTION_DAYS = int(os.getenv("OSINT_RETENTION_DAYS", "90"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    client_ip TEXT,
    analyst TEXT NOT NULL,
    module TEXT NOT NULL,
    target TEXT NOT NULL,
    purpose TEXT NOT NULL,
    legal_basis TEXT,
    case_ref TEXT,
    result TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);
"""
# tamper-evidence: each row stores the previous row's hash and its own; editing or deleting a row in the middle
# breaks the chain (verify()). Retention purges remove the oldest rows, so the chain may start after a purge.
CHAIN_FIELDS = ("ts", "tenant", "client_ip", "analyst", "module", "target", "purpose", "legal_basis", "case_ref",
                "result", "prev_hash")


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(settings.db_path) or ".", exist_ok=True)
    c = sqlite3.connect(settings.db_path)
    c.row_factory = sqlite3.Row
    return c


def init() -> None:
    with _lock, _conn() as c:
        c.executescript(SCHEMA)
        cols = {r["name"] for r in c.execute("PRAGMA table_info(scans)")}
        for col, ddl in (("tenant", "TEXT NOT NULL DEFAULT 'default'"), ("prev_hash", "TEXT"), ("hash", "TEXT")):
            if col not in cols:
                c.execute(f"ALTER TABLE scans ADD COLUMN {col} {ddl}")


def _row_hash(row: dict) -> str:
    payload = json.dumps([row.get(k) for k in CHAIN_FIELDS], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def record(*, client_ip: str, analyst: str, module: str, target: str, purpose: str,
           legal_basis: str | None, case_ref: str | None, result: dict, tenant: str = "default") -> int:
    row = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "tenant": tenant, "client_ip": client_ip,
           "analyst": analyst, "module": module, "target": target, "purpose": purpose, "legal_basis": legal_basis,
           "case_ref": case_ref, "result": json.dumps(result, ensure_ascii=False, default=str)}
    with _lock, _conn() as c:
        last = c.execute("SELECT hash FROM scans WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        row["prev_hash"] = last["hash"] if last else "genesis"
        row["hash"] = _row_hash(row)
        cols = list(row)
        cur = c.execute(f"INSERT INTO scans ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                        [row[k] for k in cols])
        return cur.lastrowid


def verify() -> dict:
    """Walk the hash chain. Returns ok, rows checked and the first broken row (if any)."""
    with _lock, _conn() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id")]
    legacy = sum(1 for r in rows if not r.get("hash"))
    chained = [r for r in rows if r.get("hash")]
    prev = None
    for n, r in enumerate(chained):
        if _row_hash(r) != r["hash"]:
            return {"ok": False, "checked": n, "broken_at": r["id"], "reason": "row content changed", "legacy_rows": legacy}
        if prev is not None and r["prev_hash"] != prev:
            return {"ok": False, "checked": n, "broken_at": r["id"], "reason": "row missing or reordered before this one",
                    "legacy_rows": legacy}
        prev = r["hash"]
    return {"ok": True, "checked": len(chained), "legacy_rows": legacy,
            "starts_after_purge": bool(chained) and chained[0]["prev_hash"] != "genesis",
            "head": prev}


def history(limit: int = 50, tenant: str | None = None, module_prefix: str | None = None) -> list[dict]:
    q, args = "SELECT id, ts, tenant, analyst, module, target, purpose, legal_basis, case_ref FROM scans WHERE 1=1", []
    if tenant is not None:
        q += " AND tenant = ?"
        args.append(tenant)
    if module_prefix:
        q += " AND module LIKE ?"
        args.append(module_prefix + "%")
    with _lock, _conn() as c:
        rows = c.execute(q + " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
    return [dict(r) for r in rows]


def rows_since(ts_iso: str, tenant: str | None = None, module_prefix: str = "") -> list[dict]:
    q, args = "SELECT * FROM scans WHERE ts >= ? AND module LIKE ?", [ts_iso, module_prefix + "%"]
    if tenant is not None:
        q += " AND tenant = ?"
        args.append(tenant)
    with _lock, _conn() as c:
        out = [dict(r) for r in c.execute(q + " ORDER BY id", args)]
    for r in out:
        r["result"] = json.loads(r["result"] or "{}")
    return out


def get(scan_id: int) -> dict | None:
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["result"] = json.loads(d["result"] or "{}")
    return d


def purge_expired() -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat(timespec="seconds")
    with _lock, _conn() as c:
        return c.execute("DELETE FROM scans WHERE ts < ?", (cutoff,)).rowcount
