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
RAW_RETENTION_DAYS = int(os.getenv("SOC_RAW_RETENTION_DAYS", "7"))  # raw logs for the events explorer
INBOX_KEEP = 500 * settings.soc_scale
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
CREATE TABLE IF NOT EXISTS soc2_raw (rowid INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, ts REAL NOT NULL,
    doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_soc2_raw_ts ON soc2_raw(tenant, ts);
CREATE TABLE IF NOT EXISTS soc2_notify_rules (tenant TEXT NOT NULL, id INTEGER NOT NULL, doc TEXT NOT NULL,
    PRIMARY KEY (tenant, id));
CREATE TABLE IF NOT EXISTS soc2_inbox (rowid INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, ts REAL NOT NULL,
    read_by TEXT NOT NULL DEFAULT '[]', doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_soc2_inbox_ts ON soc2_inbox(tenant, ts);
CREATE TABLE IF NOT EXISTS soc2_settings (tenant TEXT NOT NULL, k TEXT NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (tenant, k));
CREATE TABLE IF NOT EXISTS soc2_notebooks (tenant TEXT NOT NULL, id INTEGER NOT NULL, doc TEXT NOT NULL, updated_at REAL,
    deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (tenant, id));
CREATE TABLE IF NOT EXISTS soc2_entities (tenant TEXT NOT NULL, id INTEGER NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (tenant, id));
CREATE TABLE IF NOT EXISTS soc2_intakes (tenant TEXT NOT NULL, id INTEGER NOT NULL, key_hash TEXT NOT NULL UNIQUE, doc TEXT NOT NULL,
    PRIMARY KEY (tenant, id));
CREATE TABLE IF NOT EXISTS soc2_assets (tenant TEXT NOT NULL, type TEXT NOT NULL, name TEXT NOT NULL, doc TEXT NOT NULL,
    PRIMARY KEY (tenant, type, name));
CREATE TABLE IF NOT EXISTS soc2_iocs (tenant TEXT NOT NULL, value TEXT NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (tenant, value));
CREATE TABLE IF NOT EXISTS soc2_feeds (tenant TEXT NOT NULL, id INTEGER NOT NULL, key_hash TEXT NOT NULL UNIQUE, doc TEXT NOT NULL,
    PRIMARY KEY (tenant, id));
CREATE TABLE IF NOT EXISTS soc2_graphs (tenant TEXT NOT NULL, id INTEGER NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (tenant, id));
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


def load(tenant: str = DEFAULT, event_limit: int | None = None, incident_limit: int | None = None,
         record_limit: int | None = None) -> dict:
    k = settings.soc_scale
    event_limit, incident_limit, record_limit = event_limit or 300 * k, incident_limit or 200 * k, record_limit or 2000 * k
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


def save_raw(records: list[dict], tenant: str = DEFAULT) -> None:
    if not records:
        return
    with _lock, _conn() as c:
        c.executemany("INSERT INTO soc2_raw (tenant, ts, doc) VALUES (?,?,?)",
                      [(tenant, r.get("ts") or time.time(), _dump(r)) for r in records])


def raw_between(start: float, end: float, tenant: str = DEFAULT, limit: int = 50000) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT doc FROM soc2_raw WHERE tenant = ? AND ts BETWEEN ? AND ? ORDER BY ts DESC LIMIT ?",
                         (tenant, start, end, limit))
        return [json.loads(r["doc"]) for r in rows]


def events_between(start: float, end: float, tenant: str = DEFAULT, limit: int = 100000) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT doc FROM soc2_events WHERE tenant = ? AND ts BETWEEN ? AND ? ORDER BY ts DESC LIMIT ?",
                         (tenant, start, end, limit))
        return [json.loads(r["doc"]) for r in rows]


def list_notify_rules(tenant: str = DEFAULT) -> list[dict]:
    with _lock, _conn() as c:
        return [json.loads(r["doc"]) for r in c.execute("SELECT doc FROM soc2_notify_rules WHERE tenant = ? ORDER BY id", (tenant,))]


def save_notify_rule(rule: dict, tenant: str = DEFAULT) -> dict:
    with _lock, _conn() as c:
        if rule.get("id") is None:
            rule = {**rule, "id": c.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM soc2_notify_rules WHERE tenant = ?",
                                            (tenant,)).fetchone()[0]}
        c.execute("INSERT OR REPLACE INTO soc2_notify_rules (tenant, id, doc) VALUES (?,?,?)", (tenant, rule["id"], _dump(rule)))
    return rule


def delete_notify_rule(rule_id: int, tenant: str = DEFAULT) -> bool:
    with _lock, _conn() as c:
        return c.execute("DELETE FROM soc2_notify_rules WHERE tenant = ? AND id = ?", (tenant, rule_id)).rowcount > 0


def add_inbox(item: dict, tenant: str = DEFAULT) -> None:
    with _lock, _conn() as c:
        c.execute("INSERT INTO soc2_inbox (tenant, ts, doc) VALUES (?,?,?)", (tenant, item["ts"], _dump(item)))
        c.execute("DELETE FROM soc2_inbox WHERE tenant = ? AND rowid NOT IN (SELECT rowid FROM soc2_inbox WHERE tenant = ? "
                  "ORDER BY rowid DESC LIMIT ?)", (tenant, tenant, INBOX_KEEP))


def inbox(user: str, tenant: str = DEFAULT, limit: int = 50) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT rowid, read_by, doc FROM soc2_inbox WHERE tenant = ? ORDER BY rowid DESC LIMIT ?", (tenant, limit))
        return [{**json.loads(r["doc"]), "id": r["rowid"], "read": user in json.loads(r["read_by"])} for r in rows]


def mark_inbox_read(user: str, tenant: str = DEFAULT, ids: list[int] | None = None) -> int:
    n = 0
    with _lock, _conn() as c:
        q = "SELECT rowid, read_by FROM soc2_inbox WHERE tenant = ?"
        for r in c.execute(q, (tenant,)).fetchall():
            if ids is not None and r["rowid"] not in ids:
                continue
            who = json.loads(r["read_by"])
            if user not in who:
                c.execute("UPDATE soc2_inbox SET read_by = ? WHERE rowid = ?", (json.dumps(who + [user]), r["rowid"]))
                n += 1
    return n


def get_setting(key: str, default=None, tenant: str = DEFAULT):
    with _lock, _conn() as c:
        r = c.execute("SELECT doc FROM soc2_settings WHERE tenant = ? AND k = ?", (tenant, key)).fetchone()
    return json.loads(r["doc"]) if r else default


def set_setting(key: str, value, tenant: str = DEFAULT) -> None:
    with _lock, _conn() as c:
        c.execute("INSERT OR REPLACE INTO soc2_settings (tenant, k, doc) VALUES (?,?,?)", (tenant, key, _dump(value)))


def save_notebook(nb: dict, tenant: str = DEFAULT) -> dict:
    with _lock, _conn() as c:
        if nb.get("id") is None:
            nb = {**nb, "id": c.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM soc2_notebooks WHERE tenant = ?",
                                        (tenant,)).fetchone()[0]}
        c.execute("INSERT OR REPLACE INTO soc2_notebooks (tenant, id, doc, updated_at, deleted) VALUES (?,?,?,?,?)",
                  (tenant, nb["id"], _dump(nb), time.time(), 1 if nb.get("deleted") else 0))
    return nb


def notebooks(tenant: str = DEFAULT, deleted: bool = False) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT doc FROM soc2_notebooks WHERE tenant = ? AND deleted = ? ORDER BY updated_at DESC",
                         (tenant, 1 if deleted else 0))
        return [json.loads(r["doc"]) for r in rows]


def notebook(nb_id: int, tenant: str = DEFAULT) -> dict | None:
    with _lock, _conn() as c:
        r = c.execute("SELECT doc FROM soc2_notebooks WHERE tenant = ? AND id = ?", (tenant, nb_id)).fetchone()
    return json.loads(r["doc"]) if r else None


def _next_id(c, table: str, tenant: str) -> int:
    return c.execute(f"SELECT COALESCE(MAX(id), 0) + 1 FROM {table} WHERE tenant = ?", (tenant,)).fetchone()[0]


def save_entity(ent: dict, tenant: str = DEFAULT) -> dict:
    with _lock, _conn() as c:
        if ent.get("id") is None:
            ent = {**ent, "id": _next_id(c, "soc2_entities", tenant)}
        c.execute("INSERT OR REPLACE INTO soc2_entities (tenant, id, doc) VALUES (?,?,?)", (tenant, ent["id"], _dump(ent)))
    return ent


def entities(tenant: str = DEFAULT) -> list[dict]:
    with _lock, _conn() as c:
        return [json.loads(r["doc"]) for r in c.execute("SELECT doc FROM soc2_entities WHERE tenant = ? ORDER BY id", (tenant,))]


def save_intake(intake: dict, key_hash: str, tenant: str = DEFAULT) -> dict:
    with _lock, _conn() as c:
        if intake.get("id") is None:
            intake = {**intake, "id": _next_id(c, "soc2_intakes", tenant)}
        c.execute("INSERT OR REPLACE INTO soc2_intakes (tenant, id, key_hash, doc) VALUES (?,?,?,?)",
                  (tenant, intake["id"], key_hash, _dump(intake)))
    return intake


def intakes(tenant: str = DEFAULT) -> list[dict]:
    with _lock, _conn() as c:
        return [{**json.loads(r["doc"]), "_key_hash": r["key_hash"]}
                for r in c.execute("SELECT doc, key_hash FROM soc2_intakes WHERE tenant = ? ORDER BY id", (tenant,))]


def intake_by_key(key_hash: str) -> tuple[str, dict] | None:
    with _lock, _conn() as c:
        r = c.execute("SELECT tenant, doc FROM soc2_intakes WHERE key_hash = ?", (key_hash,)).fetchone()
    return (r["tenant"], json.loads(r["doc"])) if r else None


def save_assets(assets: list[dict], tenant: str = DEFAULT) -> None:
    if not assets:
        return
    with _lock, _conn() as c:
        c.executemany("INSERT OR REPLACE INTO soc2_assets (tenant, type, name, doc) VALUES (?,?,?,?)",
                      [(tenant, a["type"], a["name"], _dump(a)) for a in assets])


def assets(tenant: str = DEFAULT, limit: int = 100000) -> list[dict]:
    with _lock, _conn() as c:
        return [json.loads(r["doc"]) for r in c.execute("SELECT doc FROM soc2_assets WHERE tenant = ? LIMIT ?", (tenant, limit))]


def save_iocs(items: list[dict], tenant: str = DEFAULT) -> None:
    with _lock, _conn() as c:
        c.executemany("INSERT OR REPLACE INTO soc2_iocs (tenant, value, doc) VALUES (?,?,?)",
                      [(tenant, i["value"].lower(), _dump(i)) for i in items])


def delete_iocs(values: list[str], tenant: str = DEFAULT) -> int:
    with _lock, _conn() as c:
        return sum(c.execute("DELETE FROM soc2_iocs WHERE tenant = ? AND value = ?", (tenant, v.lower())).rowcount for v in values)


def iocs(tenant: str = DEFAULT) -> list[dict]:
    with _lock, _conn() as c:
        return [json.loads(r["doc"]) for r in c.execute("SELECT doc FROM soc2_iocs WHERE tenant = ?", (tenant,))]


def save_feed(feed: dict, key_hash: str, tenant: str = DEFAULT) -> dict:
    with _lock, _conn() as c:
        if feed.get("id") is None:
            feed = {**feed, "id": _next_id(c, "soc2_feeds", tenant)}
        c.execute("INSERT OR REPLACE INTO soc2_feeds (tenant, id, key_hash, doc) VALUES (?,?,?,?)",
                  (tenant, feed["id"], key_hash, _dump(feed)))
    return feed


def feeds(tenant: str = DEFAULT) -> list[dict]:
    with _lock, _conn() as c:
        return [{**json.loads(r["doc"]), "_key_hash": r["key_hash"]}
                for r in c.execute("SELECT doc, key_hash FROM soc2_feeds WHERE tenant = ? ORDER BY id", (tenant,))]


def feed_by_key(key_hash: str) -> tuple[str, dict] | None:
    with _lock, _conn() as c:
        r = c.execute("SELECT tenant, doc FROM soc2_feeds WHERE key_hash = ?", (key_hash,)).fetchone()
    return (r["tenant"], json.loads(r["doc"])) if r else None


def save_graph(g: dict, tenant: str = DEFAULT) -> dict:
    with _lock, _conn() as c:
        if g.get("id") is None:
            g = {**g, "id": _next_id(c, "soc2_graphs", tenant)}
        c.execute("INSERT OR REPLACE INTO soc2_graphs (tenant, id, doc) VALUES (?,?,?)", (tenant, g["id"], _dump(g)))
    return g


def graphs(tenant: str = DEFAULT) -> list[dict]:
    with _lock, _conn() as c:
        return [json.loads(r["doc"]) for r in c.execute("SELECT doc FROM soc2_graphs WHERE tenant = ? ORDER BY id DESC", (tenant,))]


def delete_graph(gid: int, tenant: str = DEFAULT) -> bool:
    with _lock, _conn() as c:
        return c.execute("DELETE FROM soc2_graphs WHERE tenant = ? AND id = ?", (tenant, gid)).rowcount > 0


def counts_prefix(prefix: str, tenant: str = DEFAULT) -> dict:
    with _lock, _conn() as c:
        return {r["k"]: r["n"] for r in c.execute("SELECT k, n FROM soc2_counters WHERE tenant = ? AND k LIKE ?",
                                                  (tenant, prefix.replace("%", "") + "%"))}


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
                         "UNION SELECT tenant FROM soc2_agents UNION SELECT tenant FROM soc2_rules UNION SELECT tenant FROM soc2_tasks "
                         "UNION SELECT tenant FROM soc2_intakes").fetchall()
    return sorted({r[0] for r in rows})


def purge_expired(now: float | None = None) -> int:
    cutoff = (now or time.time()) - RETENTION_DAYS * 86400
    with _lock, _conn() as c:
        n = c.execute("DELETE FROM soc2_events WHERE ts < ?", (cutoff,)).rowcount
        n += c.execute("DELETE FROM soc2_agent_records WHERE ts < ?", (cutoff,)).rowcount
        n += c.execute("DELETE FROM soc2_raw WHERE ts < ?", ((now or time.time()) - RAW_RETENTION_DAYS * 86400,)).rowcount
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
