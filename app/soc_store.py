"""SQLite persistence for REAL SOC data (simulated telemetry is never stored).

Stores: alert events, incidents (with analyst workflow: status, assignee, notes), AI-agent audit
records, the registered agent inventory and endpoints seen in EDR data. On start the engine is
restored from here, so a restart keeps cases and history. Detector sliding windows (fan-out,
rotating-proxy, chain state) are not persisted and start empty after a restart.

Rows are JSON documents keyed by id; retention follows SOC_RETENTION_DAYS (default 90).
"""
import json
import os
import sqlite3
import threading
import time

from app.config import settings

_lock = threading.Lock()
RETENTION_DAYS = int(os.getenv("SOC_RETENTION_DAYS", "90"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS soc_events (id INTEGER PRIMARY KEY, ts REAL NOT NULL, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_soc_events_ts ON soc_events(ts);
CREATE TABLE IF NOT EXISTS soc_incidents (id INTEGER PRIMARY KEY, last_ts REAL NOT NULL, status TEXT, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_ts ON soc_incidents(last_ts);
CREATE TABLE IF NOT EXISTS soc_agent_records (rowid INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
    agent TEXT, session TEXT, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_soc_agent_records_ts ON soc_agent_records(ts);
CREATE TABLE IF NOT EXISTS soc_agents (id TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS soc_endpoints (host TEXT PRIMARY KEY, doc TEXT NOT NULL);
"""


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(settings.db_path) or ".", exist_ok=True)
    c = sqlite3.connect(settings.db_path)
    c.row_factory = sqlite3.Row
    return c


def _dump(d: dict) -> str:
    return json.dumps(d, ensure_ascii=False, default=str)


def init() -> None:
    with _lock, _conn() as c:
        c.executescript(SCHEMA)


def save_events(events: list[dict]) -> None:
    if events:
        with _lock, _conn() as c:
            c.executemany("INSERT OR REPLACE INTO soc_events (id, ts, doc) VALUES (?,?,?)",
                          [(e["id"], e["ts"], _dump(e)) for e in events])


def save_incidents(incidents: list[dict]) -> None:
    if incidents:
        with _lock, _conn() as c:
            c.executemany("INSERT OR REPLACE INTO soc_incidents (id, last_ts, status, doc) VALUES (?,?,?,?)",
                          [(i["id"], i["last_ts"], i["status"], _dump(i)) for i in incidents])


def save_agent_records(recs: list[dict]) -> None:
    if recs:
        with _lock, _conn() as c:
            c.executemany("INSERT INTO soc_agent_records (ts, agent, session, doc) VALUES (?,?,?,?)",
                          [(r["ts"], r.get("agent"), r.get("session"), _dump(r)) for r in recs])


def save_agents(agents: list[dict]) -> None:
    if agents:
        with _lock, _conn() as c:
            c.executemany("INSERT OR REPLACE INTO soc_agents (id, doc) VALUES (?,?)",
                          [(a["id"], _dump({k: v for k, v in a.items() if k != "recent"})) for a in agents])


def save_endpoints(endpoints: list[dict]) -> None:
    if endpoints:
        with _lock, _conn() as c:
            c.executemany("INSERT OR REPLACE INTO soc_endpoints (host, doc) VALUES (?,?)",
                          [(e["host"], _dump(e)) for e in endpoints])


def load(event_limit: int = 300, incident_limit: int = 200, record_limit: int = 2000) -> dict:
    with _lock, _conn() as c:
        ev = [json.loads(r["doc"]) for r in c.execute(
            "SELECT doc FROM soc_events ORDER BY id DESC LIMIT ?", (event_limit,))]
        inc = [json.loads(r["doc"]) for r in c.execute(
            "SELECT doc FROM soc_incidents ORDER BY last_ts DESC LIMIT ?", (incident_limit,))]
        recs = [json.loads(r["doc"]) for r in c.execute(
            "SELECT doc FROM soc_agent_records ORDER BY rowid DESC LIMIT ?", (record_limit,))]
        agents = [json.loads(r["doc"]) for r in c.execute("SELECT doc FROM soc_agents")]
        eps = [json.loads(r["doc"]) for r in c.execute("SELECT doc FROM soc_endpoints")]
        max_ev = c.execute("SELECT COALESCE(MAX(id), 0) FROM soc_events").fetchone()[0]
        max_inc = c.execute("SELECT COALESCE(MAX(id), 0) FROM soc_incidents").fetchone()[0]
    return {"events": ev[::-1], "incidents": inc, "agent_records": recs[::-1], "agents": agents,
            "endpoints": eps, "max_event_id": max_ev, "max_incident_id": max_inc}


def incidents(status: str | None = None, limit: int = 500) -> list[dict]:
    q, args = "SELECT doc FROM soc_incidents", []
    if status:
        q += " WHERE status = ?"
        args.append(status)
    q += " ORDER BY last_ts DESC LIMIT ?"
    args.append(limit)
    with _lock, _conn() as c:
        return [json.loads(r["doc"]) for r in c.execute(q, args)]


def incident(inc_id: int) -> dict | None:
    with _lock, _conn() as c:
        row = c.execute("SELECT doc FROM soc_incidents WHERE id = ?", (inc_id,)).fetchone()
    return json.loads(row["doc"]) if row else None


def purge_expired(now: float | None = None) -> int:
    cutoff = (now or time.time()) - RETENTION_DAYS * 86400
    with _lock, _conn() as c:
        n = c.execute("DELETE FROM soc_events WHERE ts < ?", (cutoff,)).rowcount
        n += c.execute("DELETE FROM soc_agent_records WHERE ts < ?", (cutoff,)).rowcount
        n += c.execute("DELETE FROM soc_incidents WHERE last_ts < ? AND status NOT IN ('open', 'investigating')",
                       (cutoff,)).rowcount
    return n
