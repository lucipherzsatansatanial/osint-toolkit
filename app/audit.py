"""SQLite audit trail and case history.

Every scan records who ran it, against what, and why. Under Thailand's PDPA,
person-related lookups (email, username) need a documented purpose and lawful
basis; this log is the evidence of that.
"""
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


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(settings.db_path) or ".", exist_ok=True)
    c = sqlite3.connect(settings.db_path)
    c.row_factory = sqlite3.Row
    return c


def init() -> None:
    with _lock, _conn() as c:
        c.executescript(SCHEMA)


def record(*, client_ip: str, analyst: str, module: str, target: str, purpose: str,
           legal_basis: str | None, case_ref: str | None, result: dict) -> int:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (ts, client_ip, analyst, module, target, purpose, legal_basis, case_ref, result)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, client_ip, analyst, module, target, purpose, legal_basis, case_ref,
             json.dumps(result, ensure_ascii=False, default=str)))
        return cur.lastrowid


def history(limit: int = 50) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT id, ts, analyst, module, target, purpose, legal_basis, case_ref FROM scans"
            " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


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
