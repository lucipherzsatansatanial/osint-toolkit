"""SQLite persistence for REAL SOC data (simulated telemetry is never stored), partitioned by tenant.

Stores: alert events, incidents (with analyst workflow), AI-agent audit records, the agent inventory, endpoints and
custom rules. Every row carries a tenant; every read is filtered by tenant, so one customer's data is never
returned to another. Tables from the single-tenant version (soc_*) are migrated into tenant "default" once.

Rows are JSON documents; retention follows SOC_RETENTION_DAYS (default 90). Detector sliding windows are not
persisted and start empty after a restart.
"""
import json
import os
import sqlite3
import threading
import time

from app.config import settings

_lock = threading.Lock()
RETENTION_DAYS = int(os.getenv("SOC_RETENTION_DAYS", "90"))
DEFAULT = "default"

SCHEMA = """
CREATE TABLE IF NOT EXISTS soc2_events (tenant TEXT NOT NULL, id INTEGER NOT NULL, ts REAL NOT NULL, doc TEXT NOT NULL,
    PRIMARY KEY (tenant, id));
CREATE INDEX IF NOT EXISTS idx_soc2_events_ts ON soc2_events(tenant, ts);
CREATE TABLE IF NOT EXISTS soc2_incidents (tenant TEXT NOT NULL, id INTEGER NOT NULL, last_ts REAL NOT NULL, status TEXT,
    doc TEXT NOT NULL, PRIMARY KEY (tenant, id));
CREATE INDEX IF NOT EXISTS idx_soc2_incidents_ts ON soc2_incidents(tenant, last_ts);
CREATE TABLE IF NOT EXISTS soc2_agent_records (rowid INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, ts REAL NOT NULL,
    agent TEXT, session TEXT, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_soc2_agent_records_ts ON soc2_agent_records(tenant, ts);
CREATE TABLE IF NOT EXISTS soc2_agents (tenant TEXT NOT NULL, id TEXT NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (tenant, id));
CREATE TABLE IF NOT EXISTS soc2_endpoints (tenant TEXT NOT NULL, host TEXT NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (tenant, host));
CREATE TABLE IF NOT EXISTS soc2_rules (tenant TEXT NOT NULL, id TEXT NOT NULL, status TEXT NOT NULL, doc TEXT NOT NULL,
    updated_at REAL, PRIMARY KEY (tenant, id));
CREATE TABLE IF NOT EXISTS soc2_tasks (tenant TEXT NOT NULL, id INTEGER NOT NULL, status TEXT NOT NULL, doc TEXT NOT NULL,
    updated_at REAL, PRIMARY KEY (tenant, id));
CREATE TABLE IF NOT EXISTS soc2_counters (tenant TEXT NOT NULL, k TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (tenant, k));
"""
LEGACY = {  # old single-tenant table -> (new table, column list)
    "soc_events": ("soc2_events", "id, ts, doc"),
    "soc_incidents": ("soc2_incidents", "id, last_ts, status, doc"),
    "soc_agent_records": ("soc2_agent_records", "ts, agent, session, doc"),
    "soc_agents": ("soc2_agents", "id, doc"),
    "soc_endpoints": ("soc2_endpoints", "host, doc"),
    "soc_rules": ("soc2_rules", "id, status, doc, updated_at"),
}


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
        have = {r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for old, (new, cols) in LEGACY.items():
            if old in have and c.execute(f"SELECT COUNT(*) FROM {new}").fetchone()[0] == 0:
                c.execute(f"INSERT INTO {new} (tenant, {cols}) SELECT ?, {cols} FROM {old}", (DEFAULT,))


def save_events(events: list[dict], tenant: str = DEFAULT) -> None:
    if events:
        with _lock, _conn() as c:
            c.executemany("INSERT OR REPLACE INTO soc2_events (tenant, id, ts, doc) VALUES (?,?,?,?)",
                          [(tenant, e["id"], e["ts"], _dump(e)) for e in events])


def save_incidents(incidents: list[dict], tenant: str = DEFAULT) -> None:
    if incidents:
        with _lock, _conn() as c:
            c.executemany("INSERT OR REPLACE INTO soc2_incidents (tenant, id, last_ts, status, doc) VALUES (?,?,?,?,?)",
                          [(tenant, i["id"], i["last_ts"], i["status"], _dump(i)) for i in incidents])


def save_agent_records(recs: list[dict], tenant: str = DEFAULT) -> None:
    if recs:
        with _lock, _conn() as c:
            c.executemany("INSERT INTO soc2_agent_records (tenant, ts, agent, session, doc) VALUES (?,?,?,?,?)",
                          [(tenant, r["ts"], r.get("agent"), r.get("session"), _dump(r)) for r in recs])


def save_agents(agents: list[dict], tenant: str = DEFAULT) -> None:
    if agents:
        with _lock, _conn() as c:
            c.executemany("INSERT OR REPLACE INTO soc2_agents (tenant, id, doc) VALUES (?,?,?)",
                          [(tenant, a["id"], _dump({k: v for k, v in a.items() if k != "recent"})) for a in agents])


def save_endpoints(endpoints: list[dict], tenant: str = DEFAULT) -> None:
    if endpoints:
        with _lock, _conn() as c:
            c.executemany("INSERT OR REPLACE INTO soc2_endpoints (tenant, host, doc) VALUES (?,?,?)",
                          [(tenant, e["host"], _dump(e)) for e in endpoints])


def load(tenant: str = DEFAULT, event_limit: int = 300, incident_limit: int = 200, record_limit: int = 2000) -> dict:
    with _lock, _conn() as c:
        q = lambda sql, *a: [json.loads(r["doc"]) for r in c.execute(sql, (tenant, *a))]  # noqa: E731
        ev = q("SELECT doc FROM soc2_events WHERE tenant = ? ORDER BY id DESC LIMIT ?", event_limit)
        inc = q("SELECT doc FROM soc2_incidents WHERE tenant = ? ORDER BY last_ts DESC LIMIT ?", incident_limit)
        recs = q("SELECT doc FROM soc2_agent_records WHERE tenant = ? ORDER BY rowid DESC LIMIT ?", record_limit)
        agents = q("SELECT doc FROM soc2_agents WHERE tenant = ?")
        eps = q("SELECT doc FROM soc2_endpoints WHERE tenant = ?")
        max_ev = c.execute("SELECT COALESCE(MAX(id), 0) FROM soc2_events WHERE tenant = ?", (tenant,)).fetchone()[0]
        max_inc = c.execute("SELECT COALESCE(MAX(id), 0) FROM soc2_incidents WHERE tenant = ?", (tenant,)).fetchone()[0]
    return {"events": ev[::-1], "incidents": inc, "agent_records": recs[::-1], "agents": agents,
            "endpoints": eps, "max_event_id": max_ev, "max_incident_id": max_inc}


def incidents(status: str | None = None, limit: int = 500, tenant: str = DEFAULT) -> list[dict]:
    q, args = "SELECT doc FROM soc2_incidents WHERE tenant = ?", [tenant]
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY last_ts DESC LIMIT ?"
    args.append(limit)
    with _lock, _conn() as c:
        return [json.loads(r["doc"]) for r in c.execute(q, args)]


def incident(inc_id: int, tenant: str = DEFAULT) -> dict | None:
    with _lock, _conn() as c:
        row = c.execute("SELECT doc FROM soc2_incidents WHERE tenant = ? AND id = ?", (tenant, inc_id)).fetchone()
    return json.loads(row["doc"]) if row else None


def save_rule(rule: dict, tenant: str = DEFAULT) -> None:
    with _lock, _conn() as c:
        c.execute("INSERT OR REPLACE INTO soc2_rules (tenant, id, status, doc, updated_at) VALUES (?,?,?,?,?)",
                  (tenant, rule["id"], rule.get("status", "disabled"), _dump(rule), time.time()))


def list_rules(tenant: str = DEFAULT) -> list[dict]:
    with _lock, _conn() as c:
        return [json.loads(r["doc"]) for r in c.execute("SELECT doc FROM soc2_rules WHERE tenant = ? ORDER BY id", (tenant,))]


def save_task(task: dict, tenant: str = DEFAULT) -> dict:
    """Insert (id None) or replace an analyst task; returns it with its id."""
    with _lock, _conn() as c:
        if task.get("id") is None:
            row = c.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM soc2_tasks WHERE tenant = ?", (tenant,)).fetchone()
            task = {**task, "id": row[0]}
        c.execute("INSERT OR REPLACE INTO soc2_tasks (tenant, id, status, doc, updated_at) VALUES (?,?,?,?,?)",
                  (tenant, task["id"], task["status"], _dump(task), time.time()))
    return task


def task(task_id: int, tenant: str = DEFAULT) -> dict | None:
    with _lock, _conn() as c:
        r = c.execute("SELECT doc FROM soc2_tasks WHERE tenant = ? AND id = ?", (tenant, task_id)).fetchone()
    return json.loads(r["doc"]) if r else None


def list_tasks(tenant: str = DEFAULT, limit: int = 1000) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT doc FROM soc2_tasks WHERE tenant = ? ORDER BY id DESC LIMIT ?", (tenant, limit))
        return [json.loads(r["doc"]) for r in rows]


def add_counts(counts: dict, tenant: str = DEFAULT) -> None:
    if not counts:
        return
    with _lock, _conn() as c:
        c.executemany("INSERT INTO soc2_counters (tenant, k, n) VALUES (?,?,?) "
                      "ON CONFLICT(tenant, k) DO UPDATE SET n = n + excluded.n",
                      [(tenant, k, int(n)) for k, n in counts.items()])


def counts(tenant: str = DEFAULT) -> dict:
    with _lock, _conn() as c:
        return {r["k"]: r["n"] for r in c.execute("SELECT k, n FROM soc2_counters WHERE tenant = ?", (tenant,))}


def tenants() -> list[str]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT tenant FROM soc2_incidents UNION SELECT tenant FROM soc2_events "
                         "UNION SELECT tenant FROM soc2_agents UNION SELECT tenant FROM soc2_rules UNION SELECT tenant FROM soc2_tasks").fetchall()
    return sorted({r[0] for r in rows})


def purge_expired(now: float | None = None) -> int:
    cutoff = (now or time.time()) - RETENTION_DAYS * 86400
    with _lock, _conn() as c:
        n = c.execute("DELETE FROM soc2_events WHERE ts < ?", (cutoff,)).rowcount
        n += c.execute("DELETE FROM soc2_agent_records WHERE ts < ?", (cutoff,)).rowcount
        n += c.execute("DELETE FROM soc2_incidents WHERE last_ts < ? AND status NOT IN ('open', 'investigating')",
                       (cutoff,)).rowcount
    return n


def backup(dest_path: str) -> None:
    """Consistent online copy of the whole database (SQLite backup API)."""
    with _lock, _conn() as src:
        dst = sqlite3.connect(dest_path)
        try:
            src.backup(dst)
        finally:
            dst.close()


def writable() -> bool:
    try:
        with _lock, _conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS soc2_health (k TEXT PRIMARY KEY, v REAL)")
            c.execute("INSERT OR REPLACE INTO soc2_health (k, v) VALUES ('probe', ?)", (time.time(),))
        return True
    except sqlite3.Error:
        return False
