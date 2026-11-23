"""OSINT Toolkit — FastAPI entry point."""
import asyncio
import csv
import hashlib
import hmac
import io
import os
import tempfile
import json
import re
import secrets
import time
from collections import Counter, defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from starlette.background import BackgroundTask
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import audit, rbac
from app import ai, assistant, catalog, demo_requests, demo_tasks, threatmap, vt, explorer, integrations, intel, ingest, landscape, notify_rules, phase3, phase4, query, soc_report, soc_store, workspace
from app import query as query_mod
from app.notify import notifier
from app.telemetry import hub
from app.config import settings
from app.modules import brand, domain, email, ip, threatintel, username
from app.validators import (ValidationError, normalize_domain, normalize_email, normalize_ip,
                            normalize_keyword, normalize_username)

STATIC = Path(__file__).resolve().parent.parent / "static"
PERSONAL_DATA_MODULES = {"email", "username"}
LEGAL_BASES = ["consent", "contract", "legal_obligation", "vital_interest",
               "public_task", "legitimate_interest", "own_asset"]


def _on_incident(tenant: str, inc: dict) -> bool:
    """Engine hook: tenant notification rules first (in-app + chosen channels), then the global channel policy.
    Returns True when the incident changed (notified_sev / rule_fired) so the engine persists it."""
    try:
        fired = notify_rules.evaluate(tenant, inc, external=notifier.queue_rule)
    except Exception:  # noqa: BLE001 - a broken rule must never stop correlation
        fired = []
    return bool(notifier.offer(inc)) or bool(fired)


@asynccontextmanager
async def lifespan(_: FastAPI):
    audit.init()
    audit.purge_expired()
    rbac.init()
    soc_store.init()
    soc_store.purge_expired()
    notifier.reload()
    notifier.start()

    def setup_engine(e):  # runs once per tenant engine: restore its data, rules and alert hook
        e.restore(soc_store.load(e.tenant))
        e.custom.load(soc_store.list_rules(e.tenant))
        e.disabled_rules = set(soc_store.get_setting("disabled_rules", [], e.tenant))
        e.assets.update({(a["type"], a["name"]): a for a in soc_store.assets(e.tenant)})
        e.ioc_lookup = lambda t=e.tenant: _intel_index(t)
        e.sources.update({k[4:]: n for k, n in soc_store.counts(e.tenant).items() if k.startswith("src:")})
        e.persist = True
        e.on_incident = lambda inc, t=e.tenant: _on_incident(t, inc)
    hub.engines.clear()
    hub.setup = setup_engine
    for t in {soc_store.DEFAULT, *soc_store.tenants()}:
        hub.engine_for(t)
    backup_task = asyncio.create_task(backup_loop())
    if settings.soc_autostart:
        hub.ensure_running()  # CTI feeds + correlation ticker run even before anyone opens the dashboard
    yield
    backup_task.cancel()
    hub.stop()
    notifier.stop()


app = FastAPI(title="OSINT Toolkit", version="0.1.0", lifespan=lifespan)

_hits: dict[tuple, deque] = defaultdict(deque)


def _with_tenant(who: rbac.Principal, request: Request) -> rbac.Principal:
    """Platform staff (and the bootstrap key) choose the tenant with the X-Tenant header; others are pinned."""
    if who.platform:
        t = (request.headers.get("x-tenant") or "default").strip().lower()
        if t != "default" and not rbac.TENANT_RE.match(t):
            raise HTTPException(422, "invalid X-Tenant")
        who.tenant = t
    return who


def _authenticate(request: Request, x_api_key: str) -> rbac.Principal:
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    read = request.method == "GET"  # dashboards poll read-only endpoints; scans and writes keep the tight budget
    q = _hits[(client, read)]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= (settings.read_rate_limit_per_min if read else settings.rate_limit_per_min):
        raise HTTPException(429, "rate limit exceeded")
    q.append(now)
    if settings.api_key and x_api_key and hmac.compare_digest(x_api_key, settings.api_key):
        return _with_tenant(rbac.Principal("admin (bootstrap key)", "admin", client, False, set(rbac.ALL),
                                           platform=True), request)
    user = rbac.authenticate(x_api_key, client)
    if user:
        return _with_tenant(user, request)
    if not settings.api_key and not rbac.has_users():  # local development: no credentials configured at all
        return _with_tenant(rbac.Principal("anonymous", "admin", client, False, set(rbac.ALL),
                                           platform=True), request)
    raise HTTPException(401, "invalid or missing X-API-Key")


def require(perm: str):
    """Dependency: authenticated principal holding `perm` (see app.rbac.ROLES)."""
    def dep(request: Request, x_api_key: str = Header(default="")) -> rbac.Principal:
        who = _authenticate(request, x_api_key)
        if not who.can(perm):
            raise HTTPException(403, f"role '{who.role}' lacks permission '{perm}'")
        return who
    return dep


def need(who: rbac.Principal, *perms: str) -> None:
    """Run-time permission check for actions decided by the request body (e.g. closing vs editing a case)."""
    missing = [p for p in perms if not who.can(p)]
    if missing:
        raise HTTPException(403, f"role '{who.role}' lacks permission '{missing[0]}'")


def E(who: rbac.Principal):
    """The SOC engine of the caller's tenant — every SOC handler goes through this."""
    return hub.engine_for(who.tenant)


def actor(who: rbac.Principal, typed: str | None) -> str:
    """Name written to the audit log: the authenticated user; a typed name only for the shared bootstrap key."""
    if who.named:
        return who.name
    if not typed or len(typed.strip()) < 2:
        raise HTTPException(422, "analyst: required when using the shared key")
    return typed.strip()[:80]


class ScanRequest(BaseModel):
    module: Literal["domain", "ip", "email", "brand", "username"]
    target: str = Field(min_length=1, max_length=300)
    keyword: str | None = Field(default=None, max_length=40)
    analyst: str | None = Field(default=None, max_length=80)  # ignored for named users
    purpose: str = Field(min_length=5, max_length=500)
    legal_basis: str | None = None
    case_ref: str | None = Field(default=None, max_length=80)


async def run_scan(req: ScanRequest) -> tuple[str, dict]:
    if req.module == "domain":
        t = normalize_domain(req.target)
        return t, await domain.scan(t)
    if req.module == "ip":
        t = normalize_ip(req.target)
        return t, await ip.scan(t)
    if req.module == "email":
        t = normalize_email(req.target)
        return t, await email.scan(t)
    if req.module == "brand":
        t = normalize_domain(req.target)
        kw = normalize_keyword(req.keyword or brand.split_domain(t)[0])
        return t, await brand.scan(t, kw)
    t = normalize_username(req.target)
    return t, await username.scan(t)


@app.post("/api/scan")
async def scan(req: ScanRequest, who: rbac.Principal = Depends(require("osint.scan"))):
    if req.module in PERSONAL_DATA_MODULES and req.legal_basis not in LEGAL_BASES:
        raise HTTPException(422, "this module processes personal data: choose a PDPA legal basis")
    if req.legal_basis and req.legal_basis not in LEGAL_BASES:
        raise HTTPException(422, "unknown legal_basis")
    try:
        target, result = await run_scan(req)
    except ValidationError as e:
        raise HTTPException(422, str(e)) from e
    scan_id = audit.record(tenant=who.tenant, client_ip=who.ip, analyst=actor(who, req.analyst), module=req.module, target=target,
                           purpose=req.purpose, legal_basis=req.legal_basis, case_ref=req.case_ref,
                           result=result)
    return {"id": scan_id, "module": req.module, "target": target, "result": result}


@app.get("/api/history")
def history(limit: int = 50, who: rbac.Principal = Depends(require("osint.history"))):
    return audit.history(min(max(limit, 1), 500), tenant=who.tenant)


@app.get("/api/history.csv")
def history_csv(limit: int = 500, who: rbac.Principal = Depends(require("osint.export"))):
    rows = audit.history(min(max(limit, 1), 5000), tenant=who.tenant)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "ts", "analyst", "module", "target", "purpose", "legal_basis", "case_ref"])
    for r in rows:
        w.writerow([r.get("id"), r.get("ts"), soc_report._cell(r.get("analyst") or ""), r.get("module"),
                    soc_report._cell(r.get("target") or ""), soc_report._cell(r.get("purpose") or ""),
                    r.get("legal_basis"), soc_report._cell(r.get("case_ref") or "")])
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="osint.export", target=f"{len(rows)} scans",
                 purpose="export scan history", legal_basis="own_asset", case_ref=None, result={"rows": len(rows)})
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="osint-history.csv"'})


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: int, who: rbac.Principal = Depends(require("osint.history"))):
    row = audit.get(scan_id)
    if row and row.get("tenant", "default") != who.tenant:
        row = None
    if not row:
        raise HTTPException(404, "not found")
    return row


@app.get("/api/meta")
def meta():
    return {
        "auth_required": bool(settings.api_key) or rbac.has_users(),
        "legal_bases": LEGAL_BASES,
        "personal_data_modules": sorted(PERSONAL_DATA_MODULES),
        "integrations": {"hibp": bool(settings.hibp_api_key), "ipinfo": bool(settings.ipinfo_token),
                         "virustotal": vt.enabled()},
        "retention_days": audit.RETENTION_DAYS,
    }


# ---------- SOC dashboard: EDR / XDR / CTI ----------
# Engine state is mutated by the background tick on the event loop, so these handlers are
# async (run on the same loop) rather than sync (threadpool) to avoid concurrent mutation.
# ---------- identity & user management ----------
@app.get("/api/me")
def me(request: Request, x_api_key: str = Header(default="")):
    who = _authenticate(request, x_api_key)
    return {"name": who.name, "role": who.role, "role_th": rbac.ROLE_TH.get(who.role, who.role),
            "tenant": who.tenant, "platform": who.platform,
            "named": who.named, "permissions": sorted(who.perms)}


# ---------- roles and permissions ----------
@app.get("/api/roles")
def roles_list(who: rbac.Principal = Depends(require("users.read"))):
    groups: dict[str, list] = {}
    for pid, (grp, desc) in rbac.PERMISSIONS.items():
        groups.setdefault(grp, []).append({"id": pid, "description": desc})
    return {"roles": rbac.all_roles(who.tenant), "permissions": [{"group": g, "items": v} for g, v in groups.items()],
            "mine": sorted(who.perms)}


class RoleIn(BaseModel):
    label: str = Field(default="", max_length=60)
    permissions: list[str] = Field(min_length=1, max_length=len(rbac.PERMISSIONS))


def _no_escalation(who: rbac.Principal, perms: set[str]) -> None:
    extra = perms - who.perms
    if extra:
        raise HTTPException(403, f"cannot grant permissions you do not hold: {', '.join(sorted(extra))}")


@app.put("/api/roles/{name}")
def roles_save(name: str, req: RoleIn, who: rbac.Principal = Depends(require("roles.manage"))):
    perms = set(req.permissions)
    unknown = perms - rbac.ALL
    if unknown:
        raise HTTPException(422, f"unknown permissions: {', '.join(sorted(unknown))}")
    _no_escalation(who, perms)
    try:
        role = rbac.save_role(who.tenant, name, req.label, perms, who.name)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="rbac.role", target=f"role:{name}",
                 purpose=", ".join(sorted(perms))[:300], legal_basis="own_asset", case_ref=None, result={"perms": len(perms)})
    return role


@app.delete("/api/roles/{name}")
def roles_delete(name: str, who: rbac.Principal = Depends(require("roles.manage"))):
    try:
        ok = rbac.delete_role(who.tenant, name)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    if not ok:
        raise HTTPException(404, "role not found")
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="rbac.role", target=f"role:{name}",
                 purpose="delete", legal_basis="own_asset", case_ref=None, result={})
    return {"deleted": name}


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=63)
    tenant: str | None = Field(default=None, max_length=41)  # platform staff only; "*" = platform user
    role: str = Field(min_length=2, max_length=31)


class UserUpdate(BaseModel):
    role: str | None = Field(default=None, min_length=2, max_length=31)
    disabled: bool | None = None


@app.get("/api/users")
def users_list(who: rbac.Principal = Depends(require("users.read"))):
    return {"users": rbac.list_users(None if who.platform else who.tenant),
            "roles": [{"id": r["name"], "th": r["label"], "permissions": r["perms"], "custom": r["custom"]}
                      for r in rbac.all_roles(who.tenant)]}


@app.post("/api/users")
def users_create(req: UserCreate, who: rbac.Principal = Depends(require("users.manage"))):
    try:
        tenant = (req.tenant or who.tenant) if who.platform else who.tenant
        _no_escalation(who, rbac.role_perms(req.role, tenant))
        token = rbac.create_user(req.username.strip().lower(), req.role, who.name, tenant)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="rbac.create", target=req.username, purpose=f"role={req.role}",
                 legal_basis="own_asset", case_ref=None, result={"role": req.role})
    return {"username": req.username.strip().lower(), "role": req.role, "token": token,
            "note": "token แสดงครั้งเดียว — เก็บไว้ในที่ปลอดภัย"}


def _same_tenant_user(username: str, who: rbac.Principal) -> None:
    t = rbac.user_tenant(username)
    if t is None or (not who.platform and t != who.tenant):
        raise HTTPException(404, "user not found")


@app.post("/api/users/{username}/rotate")
def users_rotate(username: str, who: rbac.Principal = Depends(require("tokens.manage"))):
    _same_tenant_user(username, who)
    token = rbac.rotate(username)
    if token is None:
        raise HTTPException(404, "user not found")
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="rbac.rotate", target=username, purpose="rotate token",
                 legal_basis="own_asset", case_ref=None, result={})
    return {"username": username, "token": token}


@app.patch("/api/users/{username}")
def users_update(username: str, req: UserUpdate, who: rbac.Principal = Depends(require("users.read"))):
    _same_tenant_user(username, who)
    if req.disabled is not None:
        need(who, "users.manage")
    if req.role is not None:
        need(who, "roles.manage")
        _no_escalation(who, rbac.role_perms(req.role, rbac.user_tenant(username) or who.tenant))
    if who.named and username == who.name and (req.disabled or (req.role and req.role != "admin")):
        raise HTTPException(409, "cannot disable or demote your own account")
    try:
        ok = rbac.update(username, req.role, req.disabled)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    if not ok:
        raise HTTPException(404, "user not found")
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="rbac.update", target=username, purpose=str(req.model_dump()),
                 legal_basis="own_asset", case_ref=None, result=req.model_dump())
    return {"username": username, **{k: v for k, v in req.model_dump().items() if v is not None}}


@app.get("/api/tenants")
def tenants_list(who: rbac.Principal = Depends(require("users.read"))):
    """Platform staff: every tenant known to the system. Others: their own tenant."""
    if not who.platform:
        return {"tenants": [who.tenant], "current": who.tenant}
    names = {"default", *soc_store.tenants(), *rbac.tenants(), *hub.engines}
    return {"tenants": sorted(names), "current": who.tenant}


@app.get("/api/soc/snapshot")
async def soc_snapshot(who: rbac.Principal = Depends(require("soc.read"))):
    return E(who).snapshot()


@app.get("/api/soc/cti")
async def soc_cti(refresh: bool = False, who: rbac.Principal = Depends(require("threatintel.read"))):
    return threatintel.public(await threatintel.get_all(force=refresh))


@app.get("/api/soc/offensive-ai")
async def soc_offensive_ai(who: rbac.Principal = Depends(require("offensive.read"))):
    """Offensive AI-agent framework coverage, rule hit counts and the hunting query library."""
    return {**E(who).offai.summary(), "queries": hunting_pack()}


def hunting_pack() -> list[dict]:
    root = Path(__file__).resolve().parent.parent / "detections" / "offensive_ai"
    out = []
    for f in sorted(root.glob("*")) if root.exists() else []:
        if f.suffix in (".kql", ".spl", ".yml"):
            text = f.read_text(encoding="utf-8")
            first = next((ln for ln in text.splitlines() if ln.strip()), f.stem)
            m = re.search(r'comment\("([^"]+)"\)', first) or re.match(r"\s*(?://|title:)\s*(.+)", first)
            title = m.group(1).strip() if m else f.stem
            out.append({"file": f.name, "lang": {".kql": "KQL", ".spl": "SPL", ".yml": "Sigma"}[f.suffix],
                        "title": title, "query": text})
    return out


@app.get("/api/soc/agents")
async def soc_agents(who: rbac.Principal = Depends(require("agents.read"))):
    m = E(who).agents
    return {"agents": m.inventory(), "rules": m.rules()}


@app.get("/api/soc/agents/sessions/{sid}")
async def soc_agent_session(sid: str, who: rbac.Principal = Depends(require("agents.read"))):
    data = E(who).agents.session(sid[:20])
    if not data:
        raise HTTPException(404, "session not found")
    return data


@app.get("/api/soc/hunt")
async def soc_hunt(q: str = "", limit: int = 100, who: rbac.Principal = Depends(require("agents.read"))):
    return {"query": q[:300], "results": E(who).agents.hunt(q[:300], min(max(limit, 1), 500))}


INGEST_SOURCE = {"auto": "API", "native": "API", "ecs": "Elastic ECS", "defender": "Microsoft Defender",
                 "access_log": "Web access log"}


async def _read_body(request: Request) -> bytes:
    size = request.headers.get("content-length")
    if size and size.isdigit() and int(size) > ingest.MAX_BYTES:
        raise HTTPException(413, f"body larger than {ingest.MAX_BYTES} bytes")
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > ingest.MAX_BYTES:
            raise HTTPException(413, f"body larger than {ingest.MAX_BYTES} bytes")
    return body


def _parse(body: bytes, fmt: str, host: str | None):
    try:
        return ingest.parse(body, fmt, host)
    except ingest.IngestError as e:
        raise HTTPException(413 if "larger" in str(e) or "more than" in str(e) else 422, str(e)) from e


@app.post("/api/soc/ingest")
async def soc_ingest(request: Request, format: str = "auto", host: str | None = None,
                     who: rbac.Principal = Depends(require("ingest.submit"))):
    """Ingest real EDR / NDR / web / AI-agent telemetry. Formats: auto, native, ecs, defender, access_log."""
    records, rejected = _parse(await _read_body(request), format, host)
    result = E(who).ingest_external(records, source=INGEST_SOURCE.get(format, format))
    if not hub.has_subscribers(who.tenant):  # nobody watching: new viewers get these via the snapshot, so don't re-broadcast later
        E(who).drop_outbox()
    return {**result, "rejected": rejected, "format": format}


ASSET_FIELDS = ("host", "dest_host", "src_host", "client_host", "user", "agent")


def _key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@app.post("/api/soc/intake")
async def soc_intake_ingest(request: Request, host: str | None = None, x_intake_key: str = Header(default="")):
    """Ingest with a per-intake key (header X-Intake-Key): tenant, format, entity and mode come from the intake,
    so log shippers never hold a user token. Counts valid / invalid / warning events per day."""
    if not x_intake_key or len(x_intake_key) > 200:
        raise HTTPException(401, "missing X-Intake-Key")
    found = soc_store.intake_by_key(_key_hash(x_intake_key))
    if not found or found[1].get("disabled"):
        raise HTTPException(401, "invalid or disabled intake key")
    tenant, intake = found
    q = _hits[(("intake", intake["id"], tenant), True)]
    now_m = time.monotonic()
    while q and now_m - q[0] > 60:
        q.popleft()
    if len(q) >= settings.read_rate_limit_per_min:
        raise HTTPException(429, "rate limit exceeded")
    q.append(now_m)
    records, rejected = _parse(await _read_body(request), intake["format"], host)
    ent = next((e for e in soc_store.entities(tenant) if e["id"] == intake.get("entity_id")), None)
    eng = hub.engine_for(tenant)
    result = eng.ingest_external(records, source=intake["name"], entity=ent["name"] if ent else None,
                                 detect=(ent or {}).get("mode", "automatic") == "automatic")
    if not hub.has_subscribers(tenant):
        eng.drop_outbox()
    warn = sum(1 for r in records if r.get("_ts_warning") or not any(r.get(f) for f in ASSET_FIELDS))
    day = time.strftime("%Y-%m-%d", time.gmtime())
    soc_store.add_counts({f"intake:{intake['id']}:{day}:valid": len(records), f"intake:{intake['id']}:{day}:invalid": rejected,
                          f"intake:{intake['id']}:{day}:warning": warn}, tenant)
    intake["last_event_at"] = time.time()
    soc_store.save_intake(intake, _key_hash(x_intake_key), tenant)
    return {**result, "rejected": rejected, "warnings": warn, "intake": intake["name"]}


# ---------- intelligence database, tenant IOCs, outgoing feeds ----------
_INTEL_CACHE: dict[str, tuple[float, list, dict]] = {}


def _feed_stamp() -> tuple:
    return tuple((n, (threatintel._cache.get(n) or {}).get("fetched_at")) for n in ("threatfox", "feodo", "kev", "agentic"))


def _indicators(tenant: str) -> list[dict]:
    """All indicators for a tenant (public feeds + own IOCs), cached until a feed refreshes or the tenant edits IOCs."""
    stamp = hash(_feed_stamp())
    hit = _INTEL_CACHE.get(tenant)
    if hit and hit[0] == stamp:
        return hit[1]
    now = time.time()
    own = [i for i in soc_store.iocs(tenant) if not i.get("revoked") and not (i.get("expires") and i["expires"] < now)]
    rows = intel.from_feeds(threatintel.feed_index("threatfox"), threatintel.feed_index("feodo"),
                            threatintel.feed_index("kev"), threatintel.agentic_index()) + own
    _INTEL_CACHE[tenant] = (stamp, rows, intel.build_index(rows))
    return rows


def _intel_index(tenant: str) -> dict:
    _indicators(tenant)
    return _INTEL_CACHE[tenant][2]


def _sightings(who: rbac.Principal, values: list[str], days: int = 7) -> dict[str, dict]:
    """How often each indicator value appears in this tenant's raw logs and alerts (last `days`)."""
    want = {v.lower() for v in values}
    if not want:
        return {}
    end = time.time()
    start = end - days * 86400
    eng = E(who)
    recs = [r for r in eng.raw if (r.get("ts") or 0) >= start and not (eng.persist and r.get("simulated") is False)]
    if eng.persist:
        recs += soc_store.raw_between(start, end, who.tenant, limit=50000)
    out = {v: {"logs": 0, "alerts": 0, "last_seen": None, "hosts": set()} for v in want}
    for r in recs:
        for o in intel.observables(r) & want:
            x = out[o]
            x["logs"] += 1
            x["last_seen"] = max(x["last_seen"] or 0, r.get("ts") or 0)
            if r.get("host") or r.get("dest_host"):
                x["hosts"].add(r.get("host") or r.get("dest_host"))
    for e in _tenant_events(who, start, end):
        v = str(e.get("indicator") or e.get("remote_ip") or "").lower()
        if v in out:
            out[v]["alerts"] += 1
            out[v]["last_seen"] = max(out[v]["last_seen"] or 0, e["ts"])
    return {k: {**v, "hosts": sorted(h for h in v["hosts"] if h)[:5]} for k, v in out.items()}


@app.get("/api/soc/intel")
async def soc_intel(q: str = "", types: str = "", sources: str = "", min_conf: int = 0, page: int = 1, size: int = 25,
                    who: rbac.Principal = Depends(require("threatintel.read"))):
    rows = _indicators(who.tenant)
    size = max(10, min(size, 100))
    res = intel.search(rows, q[:20000], [t for t in types.split(",") if t], [s for s in sources.split(",") if s],
                       min_conf, limit=size, offset=(max(1, page) - 1) * size)
    sight = _sightings(who, [i["value"] for i in res["items"]])
    res["items"] = [{**i, "sightings": sight.get(i["value"].lower())} for i in res["items"]]
    res.update(page=max(1, page), pages=max(1, -(-res["total"] // size)), indexed=len(rows),
               sources=intel.SOURCES, types=list(intel.TYPES), tlp=intel.TLP)
    return res


class IocIn(BaseModel):
    values: str = Field(min_length=1, max_length=200_000)  # one per line or comma separated
    tlp: Literal["clear", "green", "amber", "amber+strict", "red"] = "amber"
    confidence: int = Field(default=80, ge=0, le=100)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    threat: str = Field(default="", max_length=120)
    description: str = Field(default="", max_length=1000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    expires_days: int | None = Field(default=None, ge=1, le=3650)
    collection_id: int | None = None
    kill_chain_phase: Literal["reconnaissance", "weaponization", "delivery", "exploitation", "installation",
                              "command-and-control", "actions-on-objectives", ""] = ""


KILL_CHAIN = ("reconnaissance", "weaponization", "delivery", "exploitation", "installation", "command-and-control",
              "actions-on-objectives")


def _collections(tenant: str) -> list[dict]:
    return soc_store.get_setting("ioc_collections", [], tenant)


@app.post("/api/soc/iocs")
async def soc_iocs_add(req: IocIn, who: rbac.Principal = Depends(require("threatintel.curate"))):
    """Add the tenant's own IOCs (bulk). They are searched with the CTI feeds, matched in logs (IOC-001) and can be
    published through outgoing feeds."""
    if req.collection_id is not None and not any(c["id"] == req.collection_id for c in _collections(who.tenant)):
        raise HTTPException(422, "unknown collection")
    now = time.time()
    good, bad = [], []
    for raw in re.split(r"[\n,]", req.values):
        raw = raw.strip()
        if not raw:
            continue
        typ, v = intel.classify(raw)
        if typ is None:
            bad.append(raw[:100])
            continue
        good.append({**intel._ind(v, typ, "tenant", req.confidence, req.tlp, req.threat or None, time.strftime("%Y-%m-%d"),
                                  None, _clean_tags(req.tags), req.description or None),
                     "severity": req.severity, "added_by": who.name, "added_at": now,
                     "expires": now + req.expires_days * 86400 if req.expires_days else None, "revoked": False,
                     "valid_from": now, "collection_id": req.collection_id, "kill_chain_phase": req.kill_chain_phase or None})
    if len(good) > 10000 * settings.soc_scale:
        raise HTTPException(413, f"max {10000 * settings.soc_scale:,} IOCs per request")
    soc_store.save_iocs(good, who.tenant)
    _INTEL_CACHE.pop(who.tenant, None)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ioc", target=f"{len(good)} IOCs",
                 purpose=f"add tlp={req.tlp} conf={req.confidence} threat={req.threat[:60]}", legal_basis="own_asset",
                 case_ref=None, result={"added": len(good), "invalid": len(bad)})
    return {"added": len(good), "invalid": bad[:50], "by_type": dict(Counter(i["type"] for i in good))}


@app.get("/api/soc/iocs")
async def soc_iocs_list(collection_id: int | None = None, q: str = "", page: int = 1, size: int = 50,
                        who: rbac.Principal = Depends(require("threatintel.read"))):
    rows = sorted(soc_store.iocs(who.tenant), key=lambda i: -(i.get("added_at") or 0))
    if collection_id is not None:
        rows = [i for i in rows if i.get("collection_id") == collection_id]
    if q:
        ql = q.lower()
        rows = [i for i in rows if ql in f"{i['value']} {i.get('threat') or ''} {i.get('description') or ''}".lower()]
    size = max(10, min(size, 200))
    pages = max(1, -(-len(rows) // size))
    page = max(1, min(page, pages))
    return {"iocs": rows[(page - 1) * size: page * size], "total": len(rows), "page": page, "pages": pages}


class CollectionIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)


@app.get("/api/soc/ioc-collections")
async def soc_collections(who: rbac.Principal = Depends(require("threatintel.read"))):
    counts = Counter(i.get("collection_id") for i in soc_store.iocs(who.tenant))
    return {"collections": [{**c, "iocs": counts.get(c["id"], 0)} for c in _collections(who.tenant)],
            "unassigned": counts.get(None, 0), "kill_chain": list(KILL_CHAIN)}


@app.post("/api/soc/ioc-collections")
async def soc_collection_create(req: CollectionIn, who: rbac.Principal = Depends(require("threatintel.curate"))):
    cur = _collections(who.tenant)
    item = {"id": max([c["id"] for c in cur] + [0]) + 1, **req.model_dump(), "created_by": who.name, "created_at": time.time()}
    soc_store.set_setting("ioc_collections", cur + [item], who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ioc_collection", target=f"collection:{item['id']}",
                 purpose=f"create: {item['name']}", legal_basis="own_asset", case_ref=None, result={})
    return item


@app.put("/api/soc/ioc-collections/{cid}")
async def soc_collection_update(cid: int, req: CollectionIn, who: rbac.Principal = Depends(require("threatintel.curate"))):
    cur = _collections(who.tenant)
    c = next((x for x in cur if x["id"] == cid), None)
    if c is None:
        raise HTTPException(404, "collection not found")
    c.update(req.model_dump(), updated_by=who.name, updated_at=time.time())
    soc_store.set_setting("ioc_collections", cur, who.tenant)
    return c


class IocRevoke(BaseModel):
    values: list[str] = Field(min_length=1, max_length=5000)
    revoked: bool = True


@app.post("/api/soc/iocs/revoke")
async def soc_iocs_revoke(req: IocRevoke, who: rbac.Principal = Depends(require("threatintel.curate"))):
    want = {intel.classify(v)[1].lower() for v in req.values}
    rows = [i for i in soc_store.iocs(who.tenant) if i["value"].lower() in want]
    for i in rows:
        i["revoked"] = req.revoked
        i["revoked_by"] = who.name if req.revoked else None
    soc_store.save_iocs(rows, who.tenant)
    _INTEL_CACHE.pop(who.tenant, None)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ioc", target=f"{len(rows)} IOCs",
                 purpose=f"revoked={req.revoked}", legal_basis="own_asset", case_ref=None, result={})
    return {"updated": len(rows)}


@app.get("/api/soc/ioc-collections/{cid}/report")
async def soc_collection_report(cid: int, days: int = 30, format: str = "json", who: rbac.Principal = Depends(require("threatintel.read"))):
    """Telemetry report: for every IOC in the collection, how often it appeared in this tenant's logs and alerts."""
    col = next((c for c in _collections(who.tenant) if c["id"] == cid), None)
    if col is None:
        raise HTTPException(404, "collection not found")
    days = max(1, min(days, 90))
    rows = [i for i in soc_store.iocs(who.tenant) if i.get("collection_id") == cid][:5000]
    sight = _sightings(who, [i["value"] for i in rows], days)
    items = [{"value": i["value"], "type": i["type"], "revoked": i.get("revoked", False), "threat": i.get("threat"),
              **(sight.get(i["value"].lower()) or {"logs": 0, "alerts": 0, "last_seen": None, "hosts": []})} for i in rows]
    items.sort(key=lambda x: (-(x["logs"] + x["alerts"]), x["value"]))
    seen = [x for x in items if x["logs"] or x["alerts"]]
    out = {"collection": col, "days": days, "generated_at": time.time(), "iocs": len(items), "seen": len(seen),
           "hosts": sorted({h for x in seen for h in x["hosts"]}), "items": items,
           "note": f"นับจาก log ดิบ (เก็บ {soc_store.RAW_RETENTION_DAYS} วัน) และ alert ของ tenant นี้เท่านั้น"}
    if format == "csv":
        need(who, "soc.export")
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["value", "type", "threat", "logs", "alerts", "last_seen", "hosts", "revoked"])
        for x in items:
            w.writerow([soc_report._cell(x["value"]), x["type"], soc_report._cell(x["threat"] or ""), x["logs"], x["alerts"],
                        time.strftime("%Y-%m-%d %H:%M", time.gmtime(x["last_seen"])) if x["last_seen"] else "",
                        soc_report._cell(" ".join(x["hosts"])), x["revoked"]])
        return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="ioc-telemetry-{cid}.csv"'})
    return out


class IocDelete(BaseModel):
    values: list[str] = Field(min_length=1, max_length=5000)


@app.post("/api/soc/iocs/delete")
async def soc_iocs_delete(req: IocDelete, who: rbac.Principal = Depends(require("threatintel.curate"))):
    n = soc_store.delete_iocs([intel.classify(v)[1] for v in req.values], who.tenant)
    _INTEL_CACHE.pop(who.tenant, None)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ioc", target=f"{n} IOCs",
                 purpose="delete", legal_basis="own_asset", case_ref=None, result={"deleted": n})
    return {"deleted": n}


class FeedIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    types: list[Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve", "user_agent"]] = Field(default_factory=list)
    sources: list[Literal["threatfox", "feodo", "kev", "agentic", "tenant"]] = Field(default_factory=list)
    min_confidence: int = Field(default=50, ge=0, le=100)
    max_tlp: Literal["clear", "green", "amber", "amber+strict"] = "green"
    format: Literal["stix", "text", "csv"] = "stix"
    sort: Literal["newest", "oldest"] = "newest"
    max_size: int = Field(default=2000, ge=1, le=100000)
    enabled: bool = True


def _feed_url(request: Request, key: str, fmt: str) -> str:
    base = notifier.public_url or str(request.base_url).rstrip("/")
    return f"{base}/feeds/{key}.{ {'stix': 'json', 'text': 'txt', 'csv': 'csv'}[fmt] }"


@app.get("/api/soc/feeds")
async def soc_feeds(who: rbac.Principal = Depends(require("threatintel.read"))):
    rows = _indicators(who.tenant)
    out = []
    for f in soc_store.feeds(who.tenant):
        f.pop("_key_hash", None)
        out.append({**f, "would_export": len(intel.select(rows, f))})
    return {"feeds": out}


@app.post("/api/soc/feeds/preview")
async def soc_feed_preview(req: FeedIn, who: rbac.Principal = Depends(require("threatintel.read"))):
    rows = intel.select(_indicators(who.tenant), req.model_dump())
    return {"count": len(rows), "sample": rows[:10], "by_type": dict(Counter(i["type"] for i in rows))}


@app.post("/api/soc/feeds")
async def soc_feed_create(req: FeedIn, request: Request, who: rbac.Principal = Depends(require("threatintel.curate"))):
    key = "fd_" + secrets.token_urlsafe(32)
    feed = soc_store.save_feed({"id": None, **req.model_dump(), "created_by": who.name, "created_at": time.time(),
                                "key_hint": key[:7] + "…" + key[-4:], "pulls": 0, "last_pull": None}, _key_hash(key), who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.feed", target=f"feed:{feed['id']}",
                 purpose=f"create: {feed['name']} format={feed['format']} max_tlp={feed['max_tlp']}", legal_basis="own_asset",
                 case_ref=None, result={})
    return {**feed, "url": _feed_url(request, key, feed["format"]),
            "note": "URL นี้มี key อยู่ในตัว — แสดงครั้งเดียว ใครมี URL ก็ดึงได้ จึงจำกัด TLP สูงสุดไว้ที่ amber+strict"}


@app.put("/api/soc/feeds/{feed_id}")
async def soc_feed_update(feed_id: int, req: FeedIn, request: Request, rotate_key: bool = False,
                          who: rbac.Principal = Depends(require("threatintel.curate"))):
    cur = next((f for f in soc_store.feeds(who.tenant) if f["id"] == feed_id), None)
    if cur is None:
        raise HTTPException(404, "feed not found")
    key_hash = cur.pop("_key_hash")
    cur.update(req.model_dump(), updated_by=who.name, updated_at=time.time())
    key = None
    if rotate_key:
        key = "fd_" + secrets.token_urlsafe(32)
        key_hash = _key_hash(key)
        cur["key_hint"] = key[:7] + "…" + key[-4:]
    soc_store.save_feed(cur, key_hash, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.feed", target=f"feed:{feed_id}",
                 purpose="rotate key" if key else f"update enabled={cur['enabled']}", legal_basis="own_asset", case_ref=None, result={})
    return {**cur, **({"url": _feed_url(request, key, cur["format"])} if key else {})}


@app.get("/feeds/{token}.{ext}")
async def public_feed(token: str, ext: str, request: Request):
    """Pull endpoint for firewalls / CTI platforms. The token in the URL is the credential (stored as SHA-256)."""
    if len(token) > 100 or ext not in ("json", "txt", "csv"):
        raise HTTPException(404, "not found")
    found = soc_store.feed_by_key(_key_hash(token))
    if not found or not found[1].get("enabled", True):
        raise HTTPException(404, "not found")  # same answer for wrong and disabled keys
    tenant, feed = found
    client = request.client.host if request.client else "unknown"
    q = _hits[(("feed", client), True)]
    now_m = time.monotonic()
    while q and now_m - q[0] > 60:
        q.popleft()
    if len(q) >= 60:
        raise HTTPException(429, "rate limit exceeded")
    q.append(now_m)
    rows = intel.select(_indicators(tenant), feed)
    feed.update(pulls=feed.get("pulls", 0) + 1, last_pull=time.time(), last_pull_ip=client)
    soc_store.save_feed(feed, _key_hash(token), tenant)
    fmt = feed["format"]
    if fmt == "stix":
        return JSONResponse(intel.to_stix(rows, feed["name"]), media_type="application/stix+json;version=2.1")
    if fmt == "csv":
        return Response(intel.to_csv(rows), media_type="text/csv; charset=utf-8")
    return Response(intel.to_text(rows), media_type="text/plain; charset=utf-8")


@app.get("/api/soc/integrations")
async def soc_integrations(who: rbac.Principal = Depends(require("soc.read"))):
    ins = soc_store.intakes(who.tenant)
    fds = soc_store.feeds(who.tenant)
    state = {"notify_channels": notifier.channels(), "ai_enabled": ai.status()["enabled"],
             "hibp": bool(settings.hibp_api_key), "ipinfo": bool(settings.ipinfo_token), "virustotal": vt.enabled(),
             "feeds_ok": {n: (threatintel._cache.get(n) or {}).get("ok") for n in ("threatfox", "feodo", "kev", "agentic")},
             "intakes": dict(Counter(i["format"] for i in ins if not i.get("disabled"))),
             "feeds_out": dict(Counter(f["format"] for f in fds if f.get("enabled", True)))}
    return {"integrations": integrations.catalog(state), "categories": list(integrations.CATEGORIES),
            "content_types": integrations.CONTENT_TYPES}


# ---------- global assistant ----------
def _assistant_tools(who: rbac.Principal) -> dict:
    eng = E(who)

    def search_alerts(q: str = "", severity: str = "", hours: int = 24):
        now = time.time()
        r = explorer.alerts_page(_tenant_events(who, now - max(1, min(int(hours), 720)) * 3600, now), dict(eng.incidents),
                                 "", severity, q, False, "urgency", 1, 30)
        keep = ("title", "host", "severity", "rule", "technique", "occurrences", "urgency", "status", "assignee",
                "incident_id", "last_ts", "threats", "real")
        return {"total": r["total"], "items": [{k: a.get(k) for k in keep} for a in r["items"]]}

    def search_cases(q: str = "", status: str = ""):
        merged = {i["id"]: i for i in soc_store.incidents(None, 500 * settings.soc_scale, who.tenant)}
        merged.update(eng.incidents)
        rows = [_case_row(i) for i in merged.values()]
        if status:
            rows = [r for r in rows if r["status"] in status.split(",")]
        if q:
            rows = [r for r in rows if q.lower() in f"{r['name']} {' '.join(r['hosts'])} {' '.join(r['tags'])}".lower()]
        rows.sort(key=lambda r: -r["updated_ts"])
        return {"total": len(rows), "items": rows[:25]}

    def get_case(case_id: int):
        inc = _find_incident(int(case_id), who)
        return {k: inc.get(k) for k in ("id", "title", "status", "severity", "priority", "verdict", "assignee", "hosts",
                                        "users", "domains", "tactics", "first_ts", "last_ts", "notes", "history")} | {
            "alerts": [{k: a.get(k) for k in ("ts", "title", "severity", "host", "user", "rule", "technique", "cti_match")}
                       for a in inc.get("alerts", [])[-40:]]}

    def run_query(query: str, minutes: int = 1440):
        try:
            plan = query_mod.parse(query)
        except query_mod.QueryError as e:
            raise ValueError(f"query error: {e}") from e
        end = time.time()
        start = end - max(1, min(int(minutes), 7 * 1440)) * 60
        if plan["source"] == "alerts":
            rows = sorted(_tenant_events(who, start, end), key=lambda e: -e["ts"])
        else:
            rows = [r for r in eng.raw if start <= (r.get("ts") or 0) <= end and not (eng.persist and r.get("simulated") is False)]
            if eng.persist:
                rows += soc_store.raw_between(start, end, who.tenant)
            rows = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]
        out = query_mod.run(plan, rows, default_limit=50)
        return {"total": out["total"], "rows": out["rows"][:50], "scanned": len(rows)}

    def search_intel(values: str):
        res = intel.search(_indicators(who.tenant), values, limit=20)
        sight = _sightings(who, [i["value"] for i in res["items"]])
        return {"total": res["total"], "not_found": res["not_found"],
                "items": [{k: i.get(k) for k in ("value", "type", "source_name", "confidence", "tlp", "threat", "first_seen")}
                          | {"sightings": sight.get(i["value"].lower())} for i in res["items"]]}

    def search_rules(q: str = ""):
        now = time.time()
        cat = catalog.catalog(soc_store.list_rules(who.tenant), eng.disabled_rules, _tenant_events(who, now - 7 * 86400, now),
                              dict(eng.incidents), now)
        ql = q.lower()
        rows = [r for r in cat["rules"] if not ql or ql in f"{r['id']} {r['title']} {r.get('technique')} {r.get('technique_name')} {r['category']}".lower()]
        return {"total": len(rows), "items": [{k: r.get(k) for k in ("id", "title", "severity", "technique", "tactic", "category",
                                                                     "enabled", "alerts_7d", "rejected_7d", "quality", "log_sources")}
                                              for r in rows[:30]]}

    def search_assets(q: str = "", type: str = ""):
        crit = soc_store.get_setting("asset_criticality", {}, who.tenant)
        rows = [a for a in _all_assets(who).values() if (not type or a["type"] == type) and (not q or q.lower() in a["name"].lower())]
        rows.sort(key=lambda a: (-a.get("alerts", 0), -(a.get("last_seen") or 0)))
        return {"total": len(rows), "items": [{k: a.get(k) for k in ("type", "name", "first_seen", "last_seen", "events", "alerts",
                                                                     "sources", "tags", "real")} | {"criticality": crit.get(a["name"], 0)}
                                              for a in rows[:30]]}

    return {"search_alerts": search_alerts, "search_cases": search_cases, "get_case": get_case, "run_query": run_query,
            "search_intel": search_intel, "search_rules": search_rules, "search_assets": search_assets}


class AssistantIn(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    history: list[dict] = Field(default_factory=list, max_length=20)


@app.get("/api/assistant/suggestions")
async def assistant_suggestions(who: rbac.Principal = Depends(require("ai.copilot"))):
    return {"suggestions": assistant.SUGGESTIONS, "ai": ai.status()}


@app.post("/api/assistant")
async def assistant_ask(req: AssistantIn, who: rbac.Principal = Depends(require("ai.copilot"))):
    out = await assistant.run(req.question, req.history, _assistant_tools(who))
    cost = ai.cost_usd(out.get("model"), out.get("usage"))
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="ai.assistant", target="assistant",
                 purpose=req.question[:200], legal_basis="own_asset", case_ref=None,
                 result={"source": out.get("source"), "model": out.get("model"), "tools": [c["tool"] for c in out.get("calls", [])],
                         **(out.get("usage") or {}), "cost_usd": cost})
    return out


# ---------- graph explorations ----------
def _graph_neighbors(who: rbac.Principal, typ: str, value: str, limit: int = 25) -> dict:
    """Neighbours of one node, built only from this tenant's alerts, raw logs (last 7 days), cases and intelligence."""
    v = value.strip()
    vl = v.lower()
    now = time.time()
    events = _tenant_events(who, now - 7 * 86400, now)
    eng = E(who)
    recs = [r for r in eng.raw if not (eng.persist and r.get("simulated") is False)]
    if eng.persist:
        recs += soc_store.raw_between(now - 7 * 86400, now, who.tenant, limit=30000)
    nodes, edges = {}, []

    def add(t, val, label=None, rel=""):
        if not val or len(nodes) >= limit:
            return
        nid = f"{t}:{val}"
        if nid == f"{typ}:{v}":
            return
        nodes.setdefault(nid, {"id": nid, "type": t, "value": str(val), "label": label or str(val)})
        edges.append({"from": f"{typ}:{v}", "to": nid, "label": rel})

    idx = _intel_index(who.tenant)
    if typ == "host":
        for e in events:
            if str(e.get("host", "")).lower() == vl:
                add("incident", e.get("incident_id"), f"INC-{e.get('incident_id')}", "alert") if e.get("incident_id") else None
                add("account", e.get("user") if e.get("user") not in telemetry_placeholders() else None, rel="alert")
                add("rule", e.get("rule"), rel="triggered")
                add("indicator", e.get("indicator") or e.get("remote_ip"), rel="contacted")
        for r in recs:
            if vl in {str(r.get(f) or "").lower() for f in ("host", "dest_host", "src_host")}:
                add("account", r.get("user") if r.get("user") not in telemetry_placeholders() else None, rel="logon/process")
                for o in intel.observables(r):
                    if o in idx:
                        add("indicator", idx[o]["value"], rel="contacted (CTI)")
    elif typ == "account":
        for e in events:
            if str(e.get("user", "")).lower() == vl:
                add("host", e.get("host"), rel="alert")
                add("incident", e.get("incident_id"), f"INC-{e.get('incident_id')}", "alert") if e.get("incident_id") else None
        for r in recs:
            if str(r.get("user") or "").lower() == vl:
                add("host", r.get("dest_host") or r.get("host"), rel=r.get("kind") or "")
                add("host", r.get("src_host"), rel="from")
    elif typ == "indicator":
        hit = idx.get(vl)
        if hit and hit.get("threat"):
            add("threat", hit["threat"], rel=hit["source_name"])
        for e in events:
            if str(e.get("indicator") or e.get("remote_ip") or "").lower() == vl:
                add("host", e.get("host"), rel="alert")
                add("incident", e.get("incident_id"), f"INC-{e.get('incident_id')}", "alert") if e.get("incident_id") else None
        for r in recs:
            if vl in intel.observables(r):
                add("host", r.get("host") or r.get("dest_host"), rel="seen in log")
    elif typ == "threat":
        for i in _indicators(who.tenant):
            if (i.get("threat") or "").lower() == vl:
                add("indicator", i["value"], rel=i["source_name"])
        for e in events:
            if (e.get("malware") or e.get("framework") or "").lower() == vl:
                add("host", e.get("host"), rel="alert")
    elif typ == "incident":
        inc = _find_incident(int(v), who)
        for h in inc.get("hosts", []):
            add("host", h, rel="impacted")
        for u in inc.get("users", []):
            add("account", u if u not in telemetry_placeholders() else None, rel="involved")
        for a in inc.get("alerts", []):
            add("rule", a.get("rule"), rel="alert")
            add("indicator", a.get("indicator"), rel="alert")
            add("threat", a.get("malware") or a.get("framework"), rel="alert")
    elif typ == "rule":
        for e in events:
            if e.get("rule") == v:
                add("host", e.get("host"), rel="fired on")
                add("incident", e.get("incident_id"), f"INC-{e.get('incident_id')}", "case") if e.get("incident_id") else None
    else:
        raise HTTPException(422, "type must be host, account, indicator, threat, incident or rule")
    seen = set()
    uniq = []
    for ed in edges:
        k = (ed["from"], ed["to"])
        if k not in seen:
            seen.add(k)
            uniq.append(ed)
    return {"node": {"id": f"{typ}:{v}", "type": typ, "value": v, "label": f"INC-{v}" if typ == "incident" else v},
            "nodes": list(nodes.values()), "edges": uniq, "truncated": len(nodes) >= limit}


def telemetry_placeholders() -> set:
    from app.telemetry import PLACEHOLDER_USERS
    return PLACEHOLDER_USERS


@app.get("/api/soc/graph/expand")
async def soc_graph_expand(type: str, value: str, limit: int = 25, who: rbac.Principal = Depends(require("query.run"))):
    return _graph_neighbors(who, type, value[:500], max(5, min(limit, 60)))


def _auto_graph(who: rbac.Principal, inc_id: int, cap: int = 45) -> dict:
    """Two-hop investigation graph around one case: the case → its hosts / accounts / rules / indicators / threats →
    what those hosts and indicators touch. Built with the same neighbour search as manual expansion."""
    root = _graph_neighbors(who, "incident", str(inc_id), 20)
    nodes = {root["node"]["id"]: {**root["node"], "expanded": True}}
    edges = list(root["edges"])
    for n in root["nodes"]:
        nodes.setdefault(n["id"], n)
    second = [n for n in root["nodes"] if n["type"] in ("host", "indicator", "account")][:5]
    for n in second:
        if len(nodes) >= cap:
            break
        sub = _graph_neighbors(who, n["type"], n["value"], 10)
        nodes[n["id"]]["expanded"] = True
        for m in sub["nodes"]:
            if len(nodes) >= cap and m["id"] not in nodes:
                continue
            nodes.setdefault(m["id"], m)
        edges += [e for e in sub["edges"] if e["to"] in nodes]
    seen, uniq = set(), []
    for e in edges:
        k = tuple(sorted((e["from"], e["to"])))
        if k not in seen and e["from"] in nodes and e["to"] in nodes:
            seen.add(k)
            uniq.append(e)
    return {"nodes": list(nodes.values()), "edges": uniq}


@app.get("/api/soc/graph/suggest")
async def soc_graph_suggest(who: rbac.Principal = Depends(require("query.run"))):
    """Where to start an investigation, from this tenant's last 24 h: severe open cases, most-alerted hosts,
    indicators seen in alerts, accounts and rules that fired most."""
    now = time.time()
    ev = [e for e in _tenant_events(who, now - 86400, now) if e.get("severity") != "info"]
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    incs = sorted((i for i in E(who).incidents.values() if i.get("status") in ("open", "investigating")),
                  key=lambda i: (sev_rank.get(i.get("severity"), 9), -(i.get("last_ts") or 0)))[:4]
    out = [{"type": "incident", "value": str(i["id"]), "label": f"INC-{i['id']}", "count": len(i.get("alerts", [])),
            "why": f"{i.get('severity')} · {str(i.get('title') or i.get('name') or '')[:60]}"} for i in incs]
    ph = telemetry_placeholders()
    for typ, field, n, why in (("host", "host", 4, "alerts 24 ชม."), ("indicator", "indicator", 3, "IOC ที่พบใน alert"),
                               ("account", "user", 3, "บัญชีที่เกี่ยวกับ alert"), ("rule", "rule", 3, "rule ที่ทำงานบ่อย")):
        c = Counter(str(e.get(field) or (e.get("remote_ip") if field == "indicator" else "") or "") for e in ev)
        for val, k in c.most_common(n + 3):
            if val and val not in ph and len([x for x in out if x["type"] == typ]) < n:
                out.append({"type": typ, "value": val, "label": val, "count": k, "why": why})
    return {"suggestions": out}


@app.get("/api/soc/graph/auto")
async def soc_graph_auto(incident: int, who: rbac.Principal = Depends(require("query.run"))):
    return _auto_graph(who, incident)


DEMO_GRAPH_TTL = 300


def _demo_graphs(who: rbac.Principal) -> list[dict]:
    """In the simulated tenant: ready-made investigation graphs of the 3 most severe simulated cases (memory only,
    negative ids, rebuilt every 5 minutes)."""
    eng = E(who)
    if not eng.simulate:
        return []
    cache = getattr(eng, "_demo_graphs", None)
    now = time.time()
    if cache and now - cache["at"] < DEMO_GRAPH_TTL:
        return cache["graphs"]
    sev_rank = {"critical": 0, "high": 1}
    incs = sorted((i for i in eng.incidents.values() if i.get("severity") in sev_rank
                   and not any(a.get("simulated") is False for a in i.get("alerts", []))),
                  key=lambda i: (sev_rank[i["severity"]], -(i.get("last_ts") or 0)))[:3]
    graphs = []
    for k, inc in enumerate(incs, start=1):
        g = _auto_graph(who, inc["id"])
        graphs.append({"id": -k, "name": f"การสืบสวน INC-{inc['id']} · {str(inc.get('title') or inc.get('name') or '')[:50]}",
                       "nodes": g["nodes"], "edges": g["edges"], "created_by": "somchai.demo", "updated_by": "somchai.demo",
                       "created_at": inc.get("first_ts") or now, "updated_at": now, "simulated": True})
    eng._demo_graphs = {"at": now, "graphs": graphs}
    return graphs


class GraphIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    nodes: list[dict] = Field(default_factory=list, max_length=500 * settings.soc_scale)
    edges: list[dict] = Field(default_factory=list, max_length=2000 * settings.soc_scale)


def _clean_graph(req: GraphIn) -> tuple[list, list]:
    nodes = [{"id": str(n.get("id"))[:300], "type": str(n.get("type"))[:20], "value": str(n.get("value"))[:300],
              "label": str(n.get("label") or n.get("value"))[:300], "x": float(n.get("x") or 0), "y": float(n.get("y") or 0)}
             for n in req.nodes if n.get("id")]
    ids = {n["id"] for n in nodes}
    edges = [{"from": str(e["from"])[:300], "to": str(e["to"])[:300], "label": str(e.get("label") or "")[:60]}
             for e in req.edges if e.get("from") in ids and e.get("to") in ids]
    return nodes, edges


@app.get("/api/soc/graphs")
async def soc_graphs(who: rbac.Principal = Depends(require("notebooks.read"))):
    demo = _demo_graphs(who) if who.can("query.run") else []
    return {"graphs": [{k: g[k] for k in ("id", "name", "created_by", "created_at", "updated_at")}
                       | {"nodes": len(g["nodes"]), "simulated": bool(g.get("simulated"))}
                       for g in soc_store.graphs(who.tenant) + demo]}


@app.get("/api/soc/graphs/{gid}")
async def soc_graph(gid: int, who: rbac.Principal = Depends(require("notebooks.read"))):
    pool = soc_store.graphs(who.tenant) if gid > 0 else (_demo_graphs(who) if who.can("query.run") else [])
    g = next((g for g in pool if g["id"] == gid), None)
    if g is None:
        raise HTTPException(404, "graph not found")
    return g


@app.post("/api/soc/graphs")
async def soc_graph_create(req: GraphIn, who: rbac.Principal = Depends(require("notebooks.write"))):
    nodes, edges = _clean_graph(req)
    now = time.time()
    return soc_store.save_graph({"id": None, "name": req.name, "nodes": nodes, "edges": edges, "created_by": who.name,
                                 "created_at": now, "updated_at": now, "updated_by": who.name}, who.tenant)


@app.put("/api/soc/graphs/{gid}")
async def soc_graph_update(gid: int, req: GraphIn, who: rbac.Principal = Depends(require("notebooks.write"))):
    g = next((g for g in soc_store.graphs(who.tenant) if g["id"] == gid), None)
    if g is None:
        raise HTTPException(404, "graph not found")
    g["nodes"], g["edges"] = _clean_graph(req)
    g.update(name=req.name, updated_at=time.time(), updated_by=who.name)
    return soc_store.save_graph(g, who.tenant)


@app.delete("/api/soc/graphs/{gid}")
async def soc_graph_delete(gid: int, who: rbac.Principal = Depends(require("notebooks.write"))):
    if not soc_store.delete_graph(gid, who.tenant):
        raise HTTPException(404, "graph not found")
    return {"deleted": gid}


# ---------- workspace settings: organisation profile, case templates ----------
SECTORS = ("Banking / Finance", "Insurance", "Government", "Healthcare", "Education", "Energy / Utilities", "Telecom",
           "Manufacturing", "Retail / E-commerce", "Transportation / Logistics", "Media", "Technology", "Other")


class ProfileIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    legal_name: str = Field(default="", max_length=200)
    domain: str = Field(default="", max_length=253)
    location: str = Field(default="", max_length=80)
    sector: str = Field(default="", max_length=60)
    size: Literal["", "1-50", "51-200", "201-1000", "1001-5000", "5000+"] = ""
    security_team_size: Literal["", "0", "1-10", "11-50", "51-200", "200+"] = ""
    dpo_contact: str = Field(default="", max_length=200)  # PDPA data protection officer, used in breach-notice drafts


PROFILE_REQUIRED = ("legal_name", "domain", "location", "sector", "size", "security_team_size")


@app.get("/api/soc/workspace")
async def soc_workspace(who: rbac.Principal = Depends(require("soc.read"))):
    prof = soc_store.get_setting("profile", {"display_name": who.tenant}, who.tenant)
    return {"profile": prof, "missing": [k for k in PROFILE_REQUIRED if not prof.get(k)], "sectors": list(SECTORS),
            "tenant": who.tenant, "templates": soc_store.get_setting("case_templates", [], who.tenant)}


@app.put("/api/soc/workspace")
async def soc_workspace_set(req: ProfileIn, who: rbac.Principal = Depends(require("governance.manage"))):
    data = req.model_dump()
    if data["domain"]:
        try:
            data["domain"] = normalize_domain(data["domain"])
        except ValidationError as e:
            raise HTTPException(422, f"domain: {e}") from e
    soc_store.set_setting("profile", {**data, "updated_by": who.name, "updated_at": time.time()}, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.workspace", target="profile",
                 purpose="update organisation profile", legal_basis="own_asset", case_ref=None, result={})
    return await soc_workspace(who)


class CaseTemplate(BaseModel):
    id: int | None = None
    name: str = Field(min_length=1, max_length=120)
    title: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=8000)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    tags: list[str] = Field(default_factory=list, max_length=30)
    tasks: list[str] = Field(default_factory=list, max_length=50)


@app.put("/api/soc/case-templates")
async def soc_case_templates(templates: list[CaseTemplate], who: rbac.Principal = Depends(require("governance.manage"))):
    if len(templates) > 50:
        raise HTTPException(422, "at most 50 templates")
    out, next_id = [], max([t.id or 0 for t in templates] + [0]) + 1
    for t in templates:
        d = t.model_dump()
        if d["id"] is None:
            d["id"], next_id = next_id, next_id + 1
        d["tags"] = _clean_tags(d["tags"])
        d["tasks"] = [x.strip()[:200] for x in d["tasks"] if x.strip()]
        out.append(d)
    soc_store.set_setting("case_templates", out, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.case_templates", target="case_templates",
                 purpose=", ".join(t["name"] for t in out)[:200] or "cleared", legal_basis="own_asset", case_ref=None, result={})
    return {"templates": out}


# ---------- governance policies (separation of duties) ----------
POLICY_DEFAULTS = {"four_eyes_response": True, "four_eyes_agents": True, "four_eyes_rules": False}


def _policies(tenant: str) -> dict:
    return {**POLICY_DEFAULTS, **soc_store.get_setting("policies", {}, tenant)}


class PolicyIn(BaseModel):
    four_eyes_response: bool = True   # response actions need a second person (respond.approve)
    four_eyes_agents: bool = True     # agent permission changes need agents.approve by someone else
    four_eyes_rules: bool = False     # the publisher of a rule must not be its last editor


@app.get("/api/soc/policies")
async def soc_policies(who: rbac.Principal = Depends(require("governance.read"))):
    return {"policies": _policies(who.tenant), "defaults": POLICY_DEFAULTS}


@app.put("/api/soc/policies")
async def soc_policies_set(req: PolicyIn, who: rbac.Principal = Depends(require("governance.manage"))):
    soc_store.set_setting("policies", req.model_dump(), who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="governance.policy", target="policies",
                 purpose=json.dumps(req.model_dump()), legal_basis="own_asset", case_ref=None, result=req.model_dump())
    return {"policies": _policies(who.tenant)}


# ---------- approvals: response actions and agent permission changes ----------
def _requests(tenant: str, key: str) -> list[dict]:
    return soc_store.get_setting(key, [], tenant)


def _save_requests(tenant: str, key: str, items: list[dict]) -> None:
    soc_store.set_setting(key, items[-500 * settings.soc_scale:], tenant)


def _new_request(who: rbac.Principal, key: str, body: dict) -> dict:
    items = _requests(who.tenant, key)
    req = {"id": max([r["id"] for r in items] + [0]) + 1, **body, "requested_by": who.name, "requested_at": time.time(),
           "status": "pending"}
    _save_requests(who.tenant, key, items + [req])
    return req


class Decision(BaseModel):
    approve: bool
    comment: str = Field(default="", max_length=500)


def _decide(who: rbac.Principal, key: str, req_id: int, d: Decision) -> dict:
    items = _requests(who.tenant, key)
    r = next((x for x in items if x["id"] == req_id), None)
    if r is None:
        raise HTTPException(404, "request not found")
    if r["status"] != "pending":
        raise HTTPException(409, f"request already {r['status']}")
    if r["requested_by"] == who.name:
        raise HTTPException(403, "separation of duties: the requester cannot approve their own request")
    r.update(status="approved" if d.approve else "rejected", decided_by=who.name, decided_at=time.time(), comment=d.comment)
    _save_requests(who.tenant, key, items)
    return r


def _do_contain(who: rbac.Principal, agent_id: str, contain: bool) -> dict:
    eng = E(who)
    if agent_id not in eng.agents.agents:
        raise HTTPException(404, "unknown agent")
    result = eng.agents.contain(agent_id, contain)
    if eng.persist and not eng.agents.agents[agent_id].get("demo"):
        soc_store.save_agents([eng.agents.agents[agent_id]], who.tenant)
    return result


def _with_demo(who: rbac.Principal, key: str) -> list[dict]:
    """Stored requests plus the demo team's requests in a simulated tenant (negative ids, simulated=True)."""
    demo = demo_requests.sync(E(who), time.time())[key]
    return sorted(_requests(who.tenant, key) + demo, key=lambda r: -r["requested_at"])[:100]


def _decide_demo(who: rbac.Principal, key: str, req_id: int, d: Decision) -> dict:
    eng = E(who)
    demo_requests.sync(eng, time.time())
    box = "resp" if key == "response_requests" else "ag"
    r = getattr(eng, "_dreq", {}).get(box, {}).get(req_id)
    if r is None:
        raise HTTPException(404, "request not found")
    if r["status"] != "pending":
        raise HTTPException(409, f"request already {r['status']}")
    if r["requested_by"] == who.name:
        raise HTTPException(403, "separation of duties: the requester cannot approve their own request")
    result = demo_requests.decide(eng, box, r, d.approve, who.name, d.comment, time.time())
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.demo_decision",
                 target=f"demo-request:{req_id}", purpose=f"{key} #{req_id} by {r['requested_by']} {d.comment}"[:500],
                 legal_basis="own_asset", case_ref=None, result={"approved": d.approve, "simulated": True})
    return {**{k: v for k, v in r.items() if not k.startswith("_")}, "result": result}


@app.get("/api/soc/response-requests")
async def soc_response_requests(who: rbac.Principal = Depends(require("cases.read"))):
    return {"requests": _with_demo(who, "response_requests"),
            "four_eyes": _policies(who.tenant)["four_eyes_response"]}


@app.post("/api/soc/response-requests/{req_id}/decision")
async def soc_response_decide(req_id: int, d: Decision, who: rbac.Principal = Depends(require("respond.approve"))):
    if req_id < 0:
        return _decide_demo(who, "response_requests", req_id, d)
    r = _decide(who, "response_requests", req_id, d)
    result = None
    if d.approve:
        result = _do_contain(who, r["agent"], r["action"] == "contain")
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name,
                 module=("soc.contain" if r["action"] == "contain" else "soc.release") if d.approve else "soc.response_rejected",
                 target=r["agent"], purpose=f"request #{req_id} by {r['requested_by']}: {r['reason']} | {d.comment}"[:500],
                 legal_basis="own_asset", case_ref=None,
                 result={"approved": d.approve, "requested_by": r["requested_by"], "simulated": True})
    return {**r, "result": result}


@app.get("/api/soc/agents/requests")
async def soc_agent_requests(who: rbac.Principal = Depends(require("agents.read"))):
    return {"requests": _with_demo(who, "agent_requests"),
            "four_eyes": _policies(who.tenant)["four_eyes_agents"]}


def _apply_agent_specs(who: rbac.Principal, specs: list[dict]) -> list[dict]:
    out = E(who).agents.register(specs)
    if E(who).persist:
        soc_store.save_agents([E(who).agents.agents[a["id"]] for a in out], who.tenant)
    return out


@app.post("/api/soc/agents/requests/{req_id}/decision")
async def soc_agent_decide(req_id: int, d: Decision, who: rbac.Principal = Depends(require("agents.approve"))):
    if req_id < 0:
        return _decide_demo(who, "agent_requests", req_id, d)
    r = _decide(who, "agent_requests", req_id, d)
    out = _apply_agent_specs(who, [r["spec"]]) if d.approve else None
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.agent_approve" if d.approve else "soc.agent_reject",
                 target=r["spec"]["id"], purpose=f"request #{req_id} by {r['requested_by']} {d.comment}"[:500],
                 legal_basis="own_asset", case_ref=None, result={"approved": d.approve})
    return {**r, "agent": out[0] if out else None}


class Lifecycle(BaseModel):
    state: Literal["active", "retired"]
    reason: str = Field(min_length=5, max_length=500)


@app.post("/api/soc/agents/{agent_id}/lifecycle")
async def soc_agent_lifecycle(agent_id: str, req: Lifecycle, who: rbac.Principal = Depends(require("agents.deploy"))):
    """Put an approved agent into service or retire it. Activity from a retired agent is blocked and alerted (AGT-011)."""
    ag = E(who).agents.agents.get(agent_id)
    if ag is None or not ag.get("registered"):
        raise HTTPException(404, "unknown or unapproved agent")
    ag["retired"] = req.state == "retired"
    ag["retired_alerted"] = False
    ag["lifecycle"] = {"state": req.state, "by": who.name, "at": time.time(), "reason": req.reason}
    if E(who).persist and not ag.get("demo"):
        soc_store.save_agents([ag], who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module=f"soc.agent_{req.state}", target=agent_id,
                 purpose=req.reason, legal_basis="own_asset", case_ref=None, result={"state": req.state})
    return E(who).agents.public(ag)


# ---------- alert actions ----------
def _alert_states(tenant: str) -> dict:
    return soc_store.get_setting("alert_state", {}, tenant)


class AlertAction(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    host: str | None = Field(default=None, max_length=255)
    action: Literal["acknowledge", "assign", "escalate", "close", "reopen"]
    assignee: str | None = Field(default=None, max_length=80)
    reason: str = Field(default="", max_length=500)
    verdict: Literal["false_positive", "benign", "true_positive", ""] = ""


ALERT_PERM = {"acknowledge": "alerts.acknowledge", "assign": "alerts.assign", "escalate": "alerts.escalate",
              "close": "alerts.close", "reopen": "alerts.close"}


@app.post("/api/soc/alerts/action")
async def soc_alert_action(req: AlertAction, who: rbac.Principal = Depends(require("alerts.read"))):
    """Act on an alert group (same alert title on the same host) without touching response capabilities."""
    perm = ALERT_PERM[req.action]
    if req.action == "assign" and who.named and req.assignee == who.name:
        perm = "alerts.acknowledge"  # taking an alert yourself
    need(who, perm)
    if req.action == "close" and len(req.reason.strip()) < 3:
        raise HTTPException(422, "closing an alert needs a reason")
    eng = E(who)
    now = time.time()
    events = [e for e in _tenant_events(who, now - 30 * 86400, now) if e.get("title") == req.title and e.get("host") == req.host]
    if not events:
        raise HTTPException(404, "alert not found")
    key = workspace.alert_key(req.title, req.host)
    states = _alert_states(who.tenant)
    st = dict(states.get(key) or {})
    result: dict = {}
    if req.action == "acknowledge":
        st.update(status="acknowledged")
    elif req.action == "assign":
        st.update(status=st.get("status") if st.get("status") not in (None, "closed") else "acknowledged",
                  assignee=_check_assignee(who, req.assignee) if req.assignee else None)
    elif req.action == "close":
        st.update(status="closed", verdict=req.verdict or None)
    elif req.action == "reopen":
        st.update(status="new", verdict=None)
    elif req.action == "escalate":
        inc_id = next((e["incident_id"] for e in reversed(events) if e.get("incident_id")), None)
        inc = eng.incidents.get(inc_id) or (soc_store.incident(inc_id, who.tenant) if inc_id else None)
        if inc and inc.get("status") not in CLOSED:
            order = ["low", "medium", "high", "critical"]
            cur = inc.get("priority") or (inc.get("severity") if inc.get("severity") in order else "medium")
            new = order[min(len(order) - 1, order.index(cur) + 1)]
            eng.update_incident(inc["id"], who.name, "investigating" if inc["status"] == "open" else None,
                                note=f"escalated from alert '{req.title}' on {req.host}: {req.reason}".strip(), priority=new)
            result = {"incident_id": inc["id"], "priority": new}
        else:
            last = events[-1]
            case = eng.create_case(who.name, f"[Escalated] {req.title}"[:200],
                                   f"ยกระดับจาก alert บน {req.host}: {req.reason}".strip(),
                                   {"critical": "critical", "high": "high"}.get(last.get("severity"), "medium"),
                                   None, ["escalated"], [req.host] if req.host else [])
            case["alerts"] = [{k: e.get(k) for k in ("id", "ts", "domain", "title", "severity", "technique", "host", "rule",
                                                     "cti_match", "user")} for e in events[-50:]]
            eng._dirty.add(case["id"])
            eng.flush()
            result = {"incident_id": case["id"], "created": True}
        st.update(status="escalated", incident_id=result["incident_id"])
    st.update(ts=now, by=who.name, reason=req.reason or st.get("reason"))
    states[key] = st
    if len(states) > 5000 * settings.soc_scale:
        for k in sorted(states, key=lambda k: states[k].get("ts", 0))[: len(states) - 5000 * settings.soc_scale]:
            states.pop(k)
    soc_store.set_setting("alert_state", states, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module=f"soc.alert_{req.action}",
                 target=f"{req.title} @ {req.host}"[:300], purpose=req.reason or req.action, legal_basis="own_asset",
                 case_ref=f"INC-{result['incident_id']}" if result.get("incident_id") else None,
                 result={k: v for k, v in st.items() if k in ("status", "assignee", "verdict")})
    return {"state": st, **result}


# ---------- entities and intakes ----------
class EntityIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    mode: Literal["automatic", "monitor"] = "automatic"  # monitor = collect logs only, raise no alerts


@app.get("/api/soc/entities")
async def soc_entities(who: rbac.Principal = Depends(require("entities.read"))):
    ins = soc_store.intakes(who.tenant)
    return {"entities": [{**e, "intakes": sum(1 for i in ins if i.get("entity_id") == e["id"])}
                         for e in soc_store.entities(who.tenant)]}


@app.post("/api/soc/entities")
async def soc_entity_create(req: EntityIn, who: rbac.Principal = Depends(require("ingest.sources.manage"))):
    if any(e["name"].lower() == req.name.strip().lower() for e in soc_store.entities(who.tenant)):
        raise HTTPException(409, "entity name already exists")
    ent = soc_store.save_entity({"id": None, **req.model_dump(), "name": req.name.strip(), "created_by": who.name,
                                 "created_at": time.time()}, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.entity", target=f"entity:{ent['id']}",
                 purpose=f"create: {ent['name']} mode={ent['mode']}", legal_basis="own_asset", case_ref=None, result={})
    return ent


@app.put("/api/soc/entities/{ent_id}")
async def soc_entity_update(ent_id: int, req: EntityIn, who: rbac.Principal = Depends(require("ingest.sources.manage"))):
    ent = next((e for e in soc_store.entities(who.tenant) if e["id"] == ent_id), None)
    if ent is None:
        raise HTTPException(404, "entity not found")
    ent.update(req.model_dump(), name=req.name.strip(), updated_by=who.name, updated_at=time.time())
    soc_store.save_entity(ent, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.entity", target=f"entity:{ent_id}",
                 purpose=f"update: {ent['name']} mode={ent['mode']}", legal_basis="own_asset", case_ref=None, result={})
    return ent


def _intake_stats(tenant: str, ids: list[int], days: int) -> dict:
    cutoff = time.strftime("%Y-%m-%d", time.gmtime(time.time() - (days - 1) * 86400))
    out = {i: {"valid": 0, "invalid": 0, "warning": 0} for i in ids}
    for k, n in soc_store.counts_prefix("intake:", tenant).items():
        _, iid, day, kind = k.split(":")
        if int(iid) in out and day >= cutoff and kind in out[int(iid)]:
            out[int(iid)][kind] += n
    return out


def _public_intake(i: dict) -> dict:
    return {k: v for k, v in i.items() if not k.startswith("_")}


@app.get("/api/soc/intakes")
async def soc_intakes(days: int = 1, who: rbac.Principal = Depends(require("entities.read"))):
    days = 1 if days not in (1, 7, 30) else days
    ins = soc_store.intakes(who.tenant)
    stats = _intake_stats(who.tenant, [i["id"] for i in ins], days)
    ents = {e["id"]: e for e in soc_store.entities(who.tenant)}
    return {"intakes": [{**_public_intake(i), **stats[i["id"]], "entity": (ents.get(i.get("entity_id")) or {}).get("name"),
                         "mode": (ents.get(i.get("entity_id")) or {}).get("mode", "automatic")} for i in ins],
            "days": days, "formats": list(ingest.FORMATS)}


class IntakeIn(BaseModel):
    name: str = Field(min_length=1, max_length=120, pattern=r"^[^<>\"'`\x00-\x1f]+$")
    format: Literal["auto", "native", "ecs", "defender", "access_log"] = "auto"
    entity_id: int | None = None


def _check_entity(who: rbac.Principal, ent_id: int | None) -> None:
    if ent_id is not None and not any(e["id"] == ent_id for e in soc_store.entities(who.tenant)):
        raise HTTPException(422, "unknown entity")


@app.post("/api/soc/intakes")
async def soc_intake_create(req: IntakeIn, who: rbac.Principal = Depends(require("ingest.sources.manage"))):
    _check_entity(who, req.entity_id)
    if any(i["name"].lower() == req.name.lower() for i in soc_store.intakes(who.tenant)):
        raise HTTPException(409, "intake name already exists")
    key = "ik_" + secrets.token_urlsafe(32)
    intake = soc_store.save_intake({"id": None, **req.model_dump(), "created_by": who.name, "created_at": time.time(),
                                    "key_hint": key[:7] + "…" + key[-4:], "disabled": False}, _key_hash(key), who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.intake", target=f"intake:{intake['id']}",
                 purpose=f"create: {intake['name']} format={intake['format']}", legal_basis="own_asset", case_ref=None, result={})
    return {**intake, "key": key, "note": "เก็บ key นี้ไว้ — ระบบเก็บเฉพาะค่า hash และจะไม่แสดงอีก"}


class IntakePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120, pattern=r"^[^<>\"'`\x00-\x1f]+$")
    entity_id: int | None = None
    clear_entity: bool = False
    disabled: bool | None = None
    rotate_key: bool = False


@app.patch("/api/soc/intakes/{intake_id}")
async def soc_intake_update(intake_id: int, req: IntakePatch, who: rbac.Principal = Depends(require("ingest.sources.manage"))):
    cur = next((i for i in soc_store.intakes(who.tenant) if i["id"] == intake_id), None)
    if cur is None:
        raise HTTPException(404, "intake not found")
    key_hash, intake = cur.pop("_key_hash"), cur
    if req.name:
        intake["name"] = req.name
    if req.entity_id is not None:
        _check_entity(who, req.entity_id)
        intake["entity_id"] = req.entity_id
    if req.clear_entity:
        intake["entity_id"] = None
    if req.disabled is not None:
        intake["disabled"] = req.disabled
    key = None
    if req.rotate_key:
        key = "ik_" + secrets.token_urlsafe(32)
        key_hash = _key_hash(key)
        intake["key_hint"] = key[:7] + "…" + key[-4:]
    intake.update(updated_by=who.name, updated_at=time.time())
    soc_store.save_intake(intake, key_hash, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.intake", target=f"intake:{intake_id}",
                 purpose="rotate key" if key else f"update disabled={intake.get('disabled')}", legal_basis="own_asset",
                 case_ref=None, result={})
    return {**intake, **({"key": key} if key else {})}


# ---------- assets ----------
ASSET_TYPES = ("host", "account", "ai_agent")


def _all_assets(who: rbac.Principal) -> dict[tuple, dict]:
    out = {(a["type"], a["name"]): a for a in soc_store.assets(who.tenant)}
    for k, a in E(who).assets.items():
        out[k] = {**out.get(k, {}), **a, "tags": (out.get(k) or a).get("tags", a["tags"]),
                  "revoked": (out.get(k) or a).get("revoked", False), "description": (out.get(k) or {}).get("description", "")}
    return out


@app.get("/api/soc/assets")
async def soc_assets_list(type: str = "", q: str = "", revoked: bool = False, tag: str = "", sort: str = "last_seen", real_only: bool = False,
                          page: int = 1, size: int = 50, who: rbac.Principal = Depends(require("assets.read"))):
    crit = soc_store.get_setting("asset_criticality", {}, who.tenant)
    rows = [{**a, "criticality": crit.get(a["name"], 0)} for a in _all_assets(who).values()]
    if real_only:
        rows = [r for r in rows if r.get("real")]
    counts = Counter(r["type"] for r in rows if not r.get("revoked"))
    if type:
        rows = [r for r in rows if r["type"] == type]
    rows = [r for r in rows if bool(r.get("revoked")) == revoked]
    if tag:
        rows = [r for r in rows if tag.lower() in (t.lower() for t in r.get("tags", []))]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in f"{r['name']} {' '.join(r.get('tags', []))} {' '.join(r.get('sources', []))}".lower()]
    keys = {"last_seen": lambda r: -(r.get("last_seen") or 0), "first_seen": lambda r: -(r.get("first_seen") or 0),
            "events": lambda r: -r.get("events", 0), "alerts": lambda r: (-r.get("alerts", 0), -(r.get("last_seen") or 0)),
            "criticality": lambda r: (-r["criticality"], -r.get("alerts", 0)), "name": lambda r: r["name"].lower()}
    rows.sort(key=keys.get(sort, keys["last_seen"]))
    size = max(10, min(size, 200))
    pages = max(1, -(-len(rows) // size))
    page = max(1, min(page, pages))
    return {"total": len(rows), "page": page, "pages": pages, "items": rows[(page - 1) * size: page * size],
            "by_type": dict(counts)}


class AssetIn(BaseModel):
    type: Literal["host", "account", "ai_agent"]
    name: str = Field(min_length=1, max_length=255)
    tags: list[str] | None = Field(default=None, max_length=30)
    description: str | None = Field(default=None, max_length=1000)
    criticality: int | None = Field(default=None, ge=0, le=5)
    revoked: bool | None = None


@app.put("/api/soc/assets")
async def soc_asset_upsert(req: AssetIn, who: rbac.Principal = Depends(require("assets.manage"))):
    """Create a manual asset or update tags / description / criticality / revoked on a discovered one."""
    name = req.name.strip()
    key = (req.type, name)
    a = _all_assets(who).get(key) or {"type": req.type, "name": name, "first_seen": time.time(), "last_seen": None,
                                      "events": 0, "alerts": 0, "sources": [], "tags": [], "revoked": False,
                                      "manual": True, "real": True}
    if req.tags is not None:
        a["tags"] = _clean_tags(req.tags)
    if req.description is not None:
        a["description"] = req.description
    if req.revoked is not None:
        a["revoked"] = req.revoked
    a["real"] = True
    E(who).assets[key] = {**E(who).assets.get(key, {}), **a}
    soc_store.save_assets([a], who.tenant)
    if req.criticality is not None:
        crit = soc_store.get_setting("asset_criticality", {}, who.tenant)
        if req.criticality:
            crit[name] = req.criticality
        else:
            crit.pop(name, None)
        soc_store.set_setting("asset_criticality", crit, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.asset", target=f"{req.type}:{name}",
                 purpose=f"upsert revoked={a.get('revoked')} criticality={req.criticality}", legal_basis="own_asset",
                 case_ref=None, result={})
    return {**a, "criticality": soc_store.get_setting("asset_criticality", {}, who.tenant).get(name, 0)}


class AgentSpec(BaseModel):
    id: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    owner: str = Field(default="", max_length=80)
    host: str = Field(default="", max_length=255)
    account: str = Field(default="", max_length=120)
    scopes: list[str] = Field(default_factory=list, max_length=200)
    egress: list[str] = Field(default_factory=list, max_length=200)
    shell: bool = False
    mcp_servers: list[str] | None = Field(default=None, max_length=200)  # None = not enforced


@app.post("/api/soc/agents/register")
async def soc_register_agents(items: list[AgentSpec], who: rbac.Principal = Depends(require("agents.edit"))):
    """Upsert real AI agents and what they are allowed to do. Unregistered agents seen in logs raise AGT-011."""
    if len(items) > 500 * settings.soc_scale:
        raise HTTPException(413, f"max {500 * settings.soc_scale} agents per request")
    specs = [{**a.model_dump(), "account": a.account or a.id} for a in items]
    if _policies(who.tenant)["four_eyes_agents"]:
        reqs = [_new_request(who, "agent_requests", {"spec": sp, "change": "new" if sp["id"] not in E(who).agents.agents
                                                     else "update"}) for sp in specs]
        audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.agent_request",
                     target=", ".join(sp["id"] for sp in specs)[:300], purpose="propose agent permissions",
                     legal_basis="own_asset", case_ref=None, result={"requests": [r["id"] for r in reqs]})
        return JSONResponse({"status": "pending_approval", "requests": reqs,
                             "note": "ต้องให้ผู้มีสิทธิ์ agents.approve คนอื่นอนุมัติก่อน สิทธิ์ใหม่จึงจะมีผล"}, status_code=202)
    out = _apply_agent_specs(who, specs)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.agent_register",
                 target=", ".join(a["id"] for a in out)[:300], purpose="register agents (four-eyes off)",
                 legal_basis="own_asset", case_ref=None, result={"agents": len(out)})
    return out


class ContainRequest(BaseModel):
    contain: bool = True
    analyst: str | None = Field(default=None, max_length=80)  # ignored for named users
    reason: str = Field(min_length=5, max_length=500)


@app.get("/api/soc/notify")
async def soc_notify_status(who: rbac.Principal = Depends(require("soc.read"))):
    """Which alert channels are configured (never returns URLs or tokens) and recent delivery results."""
    return notifier.status()


class NotifyTest(BaseModel):
    analyst: str | None = Field(default=None, max_length=80)  # ignored for named users


@app.post("/api/soc/notify/test")
async def soc_notify_test(req: NotifyTest, who: rbac.Principal = Depends(require("integrations.manage"))):
    if not notifier.channels():
        raise HTTPException(409, "no alert channel configured (set SOC_NOTIFY_* environment variables)")
    now = time.time()
    name = actor(who, req.analyst)
    sample = {"id": 0, "title": f"ทดสอบการแจ้งเตือน — ส่งโดย {name}", "severity": "high", "status": "open",
              "coordinated": False, "real": True, "hosts": ["TEST-HOST"], "users": [name], "domains": ["test"],
              "tactics": [], "rules": ["TEST"], "alerts": 0, "first_seen": now, "last_seen": now,
              "latest": "ข้อความทดสอบ ไม่ใช่เหตุการณ์จริง",
              "url": f"{notifier.public_url}/soc" if notifier.public_url else None}
    results = await notifier.deliver(sample)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=name, module="soc.notify_test", target=",".join(notifier.channels()),
                 purpose="test alert channels", legal_basis="own_asset", case_ref=None,
                 result={n: ok for n, ok, _ in results})
    return {"results": {n: {"ok": ok, "detail": str(d)} for n, ok, d in results}}


# ---------- AI SOC Copilot ----------
@app.get("/api/soc/ai/status")
async def soc_ai_status(who: rbac.Principal = Depends(require("soc.read"))):
    return ai.status()


class AiSummaryRequest(BaseModel):
    refresh: bool = False


@app.post("/api/soc/incidents/{inc_id}/ai/summary")
async def soc_ai_summary(inc_id: int, req: AiSummaryRequest, who: rbac.Principal = Depends(require("ai.copilot"))):
    """AI alert summary + AI incident timeline + response actions. Cached on the incident until refresh=true."""
    inc = _find_incident(inc_id, who)
    if inc.get("ai") and not req.refresh:
        return inc["ai"]
    out = await ai.summarize(inc)
    out["generated_at"] = time.time()
    out["generated_by"] = who.name
    inc["ai"] = out
    E(who).incidents.setdefault(inc_id, inc)
    if inc.get("real"):
        E(who)._dirty.add(inc_id)
        E(who).flush()
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ai_summary", target=f"incident:{inc_id}",
                 purpose="AI incident summary", legal_basis="own_asset", case_ref=f"INC-{inc_id}",
                 result={"source": out.get("source"), "model": out.get("model"), "redacted": out.get("redacted"),
                         "usage": out.get("usage")})
    return out


class AiAskRequest(BaseModel):
    question: str = Field(min_length=2, max_length=4000)
    history: list[dict] = Field(default_factory=list, max_length=20)


@app.post("/api/soc/incidents/{inc_id}/ai/ask")
async def soc_ai_ask(inc_id: int, req: AiAskRequest, who: rbac.Principal = Depends(require("ai.copilot"))):
    inc = _find_incident(inc_id, who)
    out = await ai.ask(inc, req.question, req.history)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ai_ask", target=f"incident:{inc_id}",
                 purpose=req.question[:300], legal_basis="own_asset", case_ref=f"INC-{inc_id}",
                 result={"source": out.get("source"), "model": out.get("model"), "redacted": out.get("redacted"),
                         "usage": out.get("usage")})
    return out


# ---------- Phase 3: NL hunting, threat enrichment, attack chains ----------
def _hunt_data(who: rbac.Principal) -> dict:
    e = E(who)
    return {"alerts": list(e.events), "agent_audit": list(e.agents.records), "incidents": list(e.incidents.values())}


class NlHuntRequest(BaseModel):
    question: str = Field(min_length=2, max_length=1000)


@app.post("/api/soc/hunt/nl")
async def soc_nl_hunt(req: NlHuntRequest, who: rbac.Principal = Depends(require("ai.hunt"))):
    out = await phase3.nl_hunt(req.question, _hunt_data(who), time.time())
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ai_hunt", target="hunt", purpose=req.question[:300],
                 legal_basis="own_asset", case_ref=None,
                 result={"mode": out.get("mode"), "total": out.get("total"), "model": out.get("model"), "usage": out.get("usage")})
    return out


class EnrichRequest(BaseModel):
    indicator: str = Field(min_length=3, max_length=500)


@app.post("/api/soc/enrich")
async def soc_enrich(req: EnrichRequest, who: rbac.Principal = Depends(require("ai.enrich"))):
    vt_res = await vt.lookup(req.indicator) if vt.enabled() and who.can("threatintel.enrich") else None
    out = await phase3.enrich(req.indicator, _hunt_data(who), vt_res)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ai_enrich", target=req.indicator[:200],
                 purpose="threat enrichment", legal_basis="own_asset", case_ref=None,
                 result={"matches": len(out["matches"]), "local_verdict": out["local_verdict"],
                         "ai": bool(out.get("ai")), "usage": (out.get("ai") or {}).get("usage")})
    return out


# ---------- VirusTotal API v3 ----------
class VtLookup(BaseModel):
    indicators: list[str] = Field(min_length=1, max_length=10)


class VtScanUrl(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    confirm_public: bool = False


@app.get("/api/soc/vt/status")
async def soc_vt_status(who: rbac.Principal = Depends(require("threatintel.read"))):
    return vt.usage()


@app.post("/api/soc/vt/lookup")
async def soc_vt_lookup(req: VtLookup, who: rbac.Principal = Depends(require("threatintel.enrich"))):
    """Reputation of up to 10 IOCs (hash / URL / domain / IP). GET look-ups only — nothing is uploaded."""
    values = list(dict.fromkeys(v.strip() for v in req.indicators if v.strip()))[:10]
    results = await vt.lookup_many(values)
    idx = _intel_index(who.tenant)
    seen = _sightings(who, [str(r.get("indicator", "")) for r in results])
    for r in results:  # local context: already in our CTI feeds / IOC collections? seen in this tenant's logs?
        key = str(r.get("indicator", "")).lower()
        hit = idx.get(key)
        r["in_intel"] = {"source": hit.get("source_name"), "threat": hit.get("threat")} if hit else None
        r["sightings"] = seen.get(key)
    spent = sum(1 for r in results if r.get("cached") is False)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.vt_lookup",
                 target=", ".join(values)[:200], purpose="IOC reputation (VirusTotal)", legal_basis="own_asset",
                 case_ref=None, result={"n": len(values), "api_calls": spent,
                                        "verdicts": [r.get("verdict") or r.get("error") for r in results]})
    return {"results": results, "usage": vt.usage()}


@app.post("/api/soc/vt/scan-url")
async def soc_vt_scan_url(req: VtScanUrl, who: rbac.Principal = Depends(require("threatintel.enrich"))):
    """Submit a URL for a fresh scan. The URL becomes visible to the VirusTotal community, hence the extra
    permission and the explicit confirmation."""
    need(who, "threatintel.curate")
    if not req.confirm_public:
        raise HTTPException(422, "ต้องยืนยันว่ายอมให้ URL นี้เปิดเผยต่อชุมชน VirusTotal (confirm_public)")
    try:
        out = await vt.submit_url(req.url)
    except vt.VTError as e:
        raise HTTPException({"unsupported": 422, "internal": 422, "disabled": 503, "quota": 429, "auth": 502}
                            .get(e.code, 502), e.message)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.vt_scan_url",
                 target=req.url[:200], purpose="submit URL to VirusTotal (public)", legal_basis="own_asset",
                 case_ref=None, result={"analysis_id": out.get("analysis_id")})
    return out


@app.get("/api/soc/chains")
async def soc_chains(who: rbac.Principal = Depends(require("cases.read"))):
    return {"chains": phase3.build_chains(list(E(who).incidents.values()))[:30]}


@app.post("/api/soc/chains/{chain_id}/ai")
async def soc_chain_ai(chain_id: str, who: rbac.Principal = Depends(require("ai.copilot"))):
    chain = next((c for c in phase3.build_chains(list(E(who).incidents.values())) if c["id"] == chain_id), None)
    if chain is None:
        raise HTTPException(404, "chain not found (chains are rebuilt from current incidents)")
    out = await ai.summarize(phase3.chain_as_incident(chain, E(who).incidents))
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ai_chain", target=chain_id, purpose="attack chain narrative",
                 legal_basis="own_asset", case_ref=chain_id,
                 result={"source": out.get("source"), "model": out.get("model"), "usage": out.get("usage")})
    return out


# ---------- Phase 5: governance, AI evaluation, HA/DR ----------
@app.get("/healthz")
def healthz():
    """Liveness: the process is up."""
    return {"ok": True}


@app.get("/readyz")
def readyz():
    """Readiness: database writable and the default tenant engine loaded."""
    ok_db = soc_store.writable()
    ok = ok_db and soc_store.DEFAULT in hub.engines
    return JSONResponse({"ok": ok, "database": ok_db, "engines": sorted(hub.engines),
                         "ticker": bool(hub.task and not hub.task.done())}, status_code=200 if ok else 503)


@app.get("/api/audit")
def audit_list(limit: int = 200, module: str | None = None, who: rbac.Principal = Depends(require("audit.read"))):
    return {"rows": audit.history(min(max(limit, 1), 2000), tenant=who.tenant, module_prefix=module)}


@app.get("/api/audit/verify")
def audit_verify(who: rbac.Principal = Depends(require("audit.read"))):
    if not who.platform:
        raise HTTPException(403, "chain verification covers every tenant — platform staff only")
    return audit.verify()


@app.get("/api/audit.csv")
def audit_csv(module: str | None = None, who: rbac.Principal = Depends(require("audit.read"))):
    rows = audit.history(5000, tenant=who.tenant, module_prefix=module)
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["id", "ts", "tenant", "analyst", "module", "target", "purpose", "legal_basis", "case_ref"]
    w.writerow(cols)
    for r in rows:
        w.writerow([soc_report._cell(r.get(c)) for c in cols])
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="audit-log.csv"'})


class Feedback(BaseModel):
    feature: Literal["summary", "ask", "hunt", "enrich", "chain", "rule"]
    ref: str = Field(min_length=1, max_length=80)
    rating: Literal["up", "down"]
    comment: str | None = Field(default=None, max_length=1000)


@app.post("/api/ai/feedback")
def ai_feedback(req: Feedback, who: rbac.Principal = Depends(require("ai.copilot"))):
    """Analyst rating of an AI answer — part of continuous AI evaluation."""
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="ai.feedback", target=f"{req.feature}:{req.ref}",
                 purpose=req.comment or req.rating, legal_basis="own_asset", case_ref=None,
                 result={"feature": req.feature, "rating": req.rating})
    return {"ok": True}


@app.get("/api/governance/ai-usage")
def ai_usage(days: int = 30, who: rbac.Principal = Depends(require("governance.read"))):
    """AI governance report: calls, tokens, estimated cost, fallbacks, grounding flags and analyst feedback."""
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - min(max(days, 1), 365) * 86400))
    rows = audit.rows_since(since, tenant=who.tenant)
    feat = defaultdict(lambda: {"calls": 0, "claude": 0, "fallback": 0, "input_tokens": 0, "output_tokens": 0,
                                "cost_usd": 0.0, "up": 0, "down": 0})
    users, daily = defaultdict(int), defaultdict(int)
    for r in rows:
        mod, res = r["module"], r["result"] or {}
        if mod == "ai.feedback":
            feat[res.get("feature", "?")]["up" if res.get("rating") == "up" else "down"] += 1
            continue
        if not mod.startswith("soc.ai") and mod != "soc.rule_draft":
            continue
        f = feat[mod.replace("soc.ai_", "").replace("soc.", "")]
        f["calls"] += 1
        users[r["analyst"]] += 1
        daily[r["ts"][:10]] += 1
        usage = res.get("usage") or {}
        if usage:
            f["claude"] += 1
            f["input_tokens"] += usage.get("input_tokens", 0)
            f["output_tokens"] += usage.get("output_tokens", 0)
            f["cost_usd"] += ai.cost_usd(res.get("model") or ai.MODEL, usage) or 0
        elif res.get("source") in ("rule-based", "none", "error", "refusal") or res.get("mode") == "keyword":
            f["fallback"] += 1
    total_cost = round(sum(f["cost_usd"] for f in feat.values()), 4)
    return {"days": days, "tenant": who.tenant, "features": {k: {**v, "cost_usd": round(v["cost_usd"], 4)} for k, v in feat.items()},
            "by_user": dict(sorted(users.items(), key=lambda x: -x[1])), "by_day": dict(sorted(daily.items())),
            "total_cost_usd": total_cost, "ai": ai.status(),
            "note": "ต้นทุนเป็นค่าประมาณจากราคาต่อ token ใน app/ai.py — ยอดจริงดูที่ Claude Console"}


@app.get("/api/admin/backup")
def admin_backup(who: rbac.Principal = Depends(require("governance.manage"))):
    """Download a consistent SQLite snapshot (all tenants) — platform staff only."""
    if not who.platform:
        raise HTTPException(403, "backups contain every tenant — platform staff only")
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    soc_store.backup(path)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="admin.backup", target="database",
                 purpose="manual backup download", legal_basis="own_asset", case_ref=None, result={"bytes": os.path.getsize(path)})
    return FileResponse(path, filename=f"soc-backup-{time.strftime('%Y%m%d-%H%M%S')}.db",
                        background=BackgroundTask(os.remove, path))


async def backup_loop() -> None:
    """Scheduled backups to SOC_BACKUP_DIR (e.g. a mounted disk / object-store sync folder), keeping N copies."""
    d = os.getenv("SOC_BACKUP_DIR", "").strip()
    if not d:
        return
    hours = float(os.getenv("SOC_BACKUP_HOURS", "24") or 24)
    keep = int(os.getenv("SOC_BACKUP_KEEP", "7") or 7)
    os.makedirs(d, exist_ok=True)
    while True:
        try:
            path = os.path.join(d, f"soc-{time.strftime('%Y%m%d-%H%M%S')}.db")
            await asyncio.to_thread(soc_store.backup, path)
            old = sorted(f for f in os.listdir(d) if f.startswith("soc-") and f.endswith(".db"))
            for f in old[:-keep]:
                os.remove(os.path.join(d, f))
        except OSError:
            pass
        await asyncio.sleep(hours * 3600)


# ---------- Phase 4: AI rule assistant, agent risk, response plans ----------
class RuleDraftRequest(BaseModel):
    description: str = Field(min_length=10, max_length=3000)


def _raw_records(who: rbac.Principal) -> list[dict]:
    return list(E(who).raw)


@app.post("/api/soc/rules/draft")
async def soc_rule_draft(req: RuleDraftRequest, who: rbac.Principal = Depends(require("rules.edit"))):
    draft = await phase4.draft_rule(req.description)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ai_rule_draft", target="rule", purpose=req.description[:300],
                 legal_basis="own_asset", case_ref=None,
                 result={"ok": "error" not in draft, "model": draft.get("model"), "usage": draft.get("usage")})
    if "error" in draft:
        return draft
    rule = phase4.assemble(draft)
    return {"draft": draft, "rule": rule, **phase4.evaluate_draft(rule, draft.get("test_cases", []), _raw_records(who))}


class RuleTestRequest(BaseModel):
    rule: dict
    test_cases: list[dict] = Field(default_factory=list, max_length=20)


@app.post("/api/soc/rules/test")
async def soc_rule_test(req: RuleTestRequest, who: rbac.Principal = Depends(require("rules.edit"))):
    rule = phase4.assemble({"local_rule": req.rule, **{k: v for k, v in req.rule.items() if k != "conditions"}})
    return {"rule": rule, **phase4.evaluate_draft(rule, req.test_cases, _raw_records(who))}


@app.get("/api/soc/rules")
async def soc_rules(who: rbac.Principal = Depends(require("rules.read"))):
    rules = soc_store.list_rules(who.tenant)
    for r in rules:
        r["hits"] = E(who).custom.hits.get(r["id"], 0)
    return {"rules": rules}


class RuleSave(BaseModel):
    rule: dict


@app.post("/api/soc/rules")
async def soc_rule_save(req: RuleSave, who: rbac.Principal = Depends(require("rules.edit"))):
    """Save a custom rule. A new rule is stored disabled as version 1; editing an existing rule stores a DRAFT —
    the live version keeps running until someone with rules.publish publishes the draft."""
    rule = phase4.assemble({"local_rule": req.rule, **{k: v for k, v in req.rule.items() if k != "conditions"}})
    errs = phase4.validate_rule(rule)
    if errs:
        raise HTTPException(422, "; ".join(errs))
    existing = {r["id"]: r for r in soc_store.list_rules(who.tenant)}
    now = time.time()
    definition = _rule_def(rule)
    if req.rule.get("id") in existing:
        cur = existing[req.rule["id"]]
        cur["draft"] = {"def": definition, "by": who.name, "at": now}
        cur["updated_at"] = now
        soc_store.save_rule(cur, who.tenant)
        out, status = cur, "draft"
    else:
        rule["id"] = f"CUS-{len(existing) + 1:03d}"
        rule.update(status="disabled", created_by=who.name, updated_at=now, version=1, draft=None,
                    versions=[{"version": 1, "def": definition, "by": who.name, "at": now, "note": "created"}])
        soc_store.save_rule(rule, who.tenant)
        out, status = rule, "disabled"
    E(who).custom.load(soc_store.list_rules(who.tenant))
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.rule_save", target=out["id"],
                 purpose=out.get("title", "")[:300], legal_basis="own_asset", case_ref=None, result={"status": status})
    return out


RULE_META = {"id", "status", "created_by", "updated_at", "status_by", "versions", "version", "draft", "hits",
             "published_by", "published_at"}


def _rule_def(rule: dict) -> dict:
    return {k: v for k, v in rule.items() if k not in RULE_META}


def _get_rule(who: rbac.Principal, rule_id: str) -> dict:
    rule = next((r for r in soc_store.list_rules(who.tenant) if r["id"] == rule_id), None)
    if rule is None:
        raise HTTPException(404, "rule not found")
    rule.setdefault("versions", [{"version": 1, "def": _rule_def(rule), "by": rule.get("created_by"),
                                  "at": rule.get("updated_at"), "note": "created"}])
    rule.setdefault("version", 1)
    return rule


def _apply_version(rule: dict, definition: dict, who: str, note: str) -> None:
    for k in list(rule):
        if k not in RULE_META:
            rule.pop(k)
    rule.update(definition)
    rule["version"] = max(v["version"] for v in rule["versions"]) + 1
    rule["versions"] = (rule["versions"] + [{"version": rule["version"], "def": definition, "by": who, "at": time.time(),
                                             "note": note}])[-20:]


class RuleStatus(BaseModel):
    status: Literal["enabled", "disabled"]


@app.patch("/api/soc/rules/{rule_id}")
async def soc_rule_status(rule_id: str, req: RuleStatus, who: rbac.Principal = Depends(require("rules.publish"))):
    """Publish (enable — applying a pending draft as a new version) or disable a custom rule."""
    rule = _get_rule(who, rule_id)
    published = None
    if req.status == "enabled":
        editor = (rule.get("draft") or {}).get("by") or rule["versions"][-1].get("by")
        if _policies(who.tenant)["four_eyes_rules"] and editor == who.name:
            raise HTTPException(403, "separation of duties: the last editor of a rule cannot publish it")
        if rule.get("draft"):
            _apply_version(rule, rule["draft"]["def"], rule["draft"]["by"], f"published by {who.name}")
            rule["draft"] = None
        published = rule["version"]
        rule.update(published_by=who.name, published_at=time.time())
    rule.update(status=req.status, status_by=who.name, updated_at=time.time())
    soc_store.save_rule(rule, who.tenant)
    E(who).custom.load(soc_store.list_rules(who.tenant))
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.rule_publish" if published else "soc.rule_status",
                 target=rule_id, purpose=req.status, legal_basis="own_asset", case_ref=None,
                 result={"status": req.status, "version": published})
    return rule


class Rollback(BaseModel):
    version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)


@app.post("/api/soc/rules/{rule_id}/rollback")
async def soc_rule_rollback(rule_id: str, req: Rollback, who: rbac.Principal = Depends(require("rules.rollback"))):
    """Restore an earlier version of a custom rule (recorded as a new version). Takes effect immediately if enabled."""
    rule = _get_rule(who, rule_id)
    old = next((v for v in rule["versions"] if v["version"] == req.version), None)
    if old is None:
        raise HTTPException(404, "version not found (only the last 20 are kept)")
    _apply_version(rule, old["def"], who.name, f"rollback to v{req.version}: {req.reason}")
    rule["updated_at"] = time.time()
    soc_store.save_rule(rule, who.tenant)
    E(who).custom.load(soc_store.list_rules(who.tenant))
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.rule_rollback", target=rule_id,
                 purpose=f"to v{req.version}: {req.reason}", legal_basis="own_asset", case_ref=None,
                 result={"version": rule["version"], "from": req.version})
    return rule


@app.get("/api/soc/agents/risk")
async def soc_agent_risk(who: rbac.Principal = Depends(require("agents.read"))):
    e, now = E(who), time.time()
    out = []
    for ag in e.agents.agents.values():
        alerts = [a for a in e.events if a.get("agent") == ag["id"] and now - a["ts"] <= 86400]
        recs = [r for r in e.agents.records if r.get("agent") == ag["id"]][-300:]
        out.append(phase4.agent_risk(ag, alerts, recs))
    return {"agents": sorted(out, key=lambda x: -x["score"])}


@app.get("/api/soc/incidents/{inc_id}/response")
async def soc_response_plan(inc_id: int, who: rbac.Principal = Depends(require("cases.read"))):
    inc = _find_incident(inc_id, who)
    return phase4.response_plan(inc, inc.get("response"))


class StepUpdate(BaseModel):
    done: bool


class PlanTasks(BaseModel):
    assignee: str | None = Field(default=None, max_length=80)
    steps: list[str] | None = Field(default=None, max_length=50)  # None = every open step


PHASE_DUE_H = {"contain": 4, "eradicate": 24, "recover": 72, "notify": 72, "lessons": 14 * 24}


@app.post("/api/soc/incidents/{inc_id}/plan-tasks")
async def soc_plan_tasks(inc_id: int, req: PlanTasks, who: rbac.Principal = Depends(require("cases.update"))):
    """Turn the open steps of the case's response plan into Tasks (skips steps already done or already a task).
    Due dates follow the phase: contain 4 h, eradicate 1 d, recover / notify 3 d (PDPA 72 h), lessons 14 d."""
    if req.assignee and req.assignee != who.name:
        need(who, "cases.assign")
    inc = _find_incident(inc_id, who)
    plan = phase4.response_plan(inc, inc.get("response"))
    have = {(t.get("incident_id"), t["name"]) for t in soc_store.list_tasks(who.tenant)}
    assignee = _check_assignee(who, req.assignee)
    now, made = time.time(), []
    for st in plan["steps"]:
        if st["done"] or (req.steps is not None and st["id"] not in req.steps) or (inc_id, st["action"][:200]) in have:
            continue
        made.append(soc_store.save_task({
            "id": None, "name": st["action"][:200], "assignee": assignee, "status": "pending",
            "description": f"{st['phase']} · ผู้รับผิดชอบตามแผน: {st['owner']} · จากแผนตอบสนองของ INC-{inc_id} (ขั้น {st['id']})",
            "due": now + PHASE_DUE_H.get(st["phase"], 24) * 3600, "incident_id": inc_id, "plan_step": st["id"],
            "created_by": who.name, "created_at": now, "updated_at": now, "history": [], "notes": []}, who.tenant))
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.task", target=f"incident:{inc_id}",
                 purpose=f"create {len(made)} tasks from response plan", legal_basis="own_asset", case_ref=f"INC-{inc_id}",
                 result={"created": [t["id"] for t in made], "assignee": assignee})
    return {"created": made, "skipped": len(plan["steps"]) - len(made)}


@app.post("/api/soc/incidents/{inc_id}/response/{step_id}")
async def soc_response_step(inc_id: int, step_id: str, req: StepUpdate,
                            who: rbac.Principal = Depends(require("cases.update"))):
    inc = _find_incident(inc_id, who)
    plan = phase4.response_plan(inc, inc.get("response"))
    if step_id not in {s["id"] for s in plan["steps"]}:
        raise HTTPException(404, "step not found")
    inc.setdefault("response", {})[step_id] = {"done": req.done, "by": who.name, "at": time.time()}
    step = next(s for s in plan["steps"] if s["id"] == step_id)
    inc.setdefault("history", []).append({"ts": time.time(), "analyst": who.name,
                                          "change": f"response {step_id} {'done' if req.done else 'reopened'}: {step['action'][:80]}"})
    E(who).incidents.setdefault(inc_id, inc)
    if inc.get("real"):
        E(who)._dirty.add(inc_id)
        E(who).flush()
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.response_step", target=f"incident:{inc_id}",
                 purpose=f"{step_id} done={req.done}", legal_basis="own_asset", case_ref=f"INC-{inc_id}",
                 result={"step": step_id, "done": req.done})
    return phase4.response_plan(inc, inc.get("response"))


class IncidentUpdate(BaseModel):
    analyst: str | None = Field(default=None, max_length=80)  # ignored for named users
    status: Literal["open", "investigating", "resolved", "false_positive", "closed"] | None = None
    assignee: str | None = Field(default=None, max_length=80)
    note: str | None = Field(default=None, max_length=4000)
    verdict: Literal["true_positive", "false_positive", "benign", "undetermined", ""] | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None
    tags: list[str] | None = Field(default=None, max_length=30)
    custom_fields: dict[str, str | int | float | None] | None = None
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=8000)


CASE_EXTRA = ("priority", "tags", "custom_fields", "name", "description")
CLOSED = ("resolved", "false_positive", "closed")


def _clean_tags(tags: list[str] | None) -> list[str] | None:
    if tags is None:
        return None
    out = []
    for t in tags:
        t = re.sub(r"\s+", " ", str(t)).strip()[:40]
        if t and t.lower() not in (x.lower() for x in out):
            out.append(t)
    return out


@app.patch("/api/soc/incidents/{inc_id}")
async def soc_update_incident(inc_id: int, req: IncidentUpdate, who: rbac.Principal = Depends(require("cases.read"))):
    """Analyst workflow: status, assignee and notes. Every change is written to the audit log."""
    extra = {k: getattr(req, k) for k in CASE_EXTRA if getattr(req, k) is not None}
    if "tags" in extra:
        extra["tags"] = _clean_tags(extra["tags"])
    if "custom_fields" in extra:
        extra["custom_fields"] = _check_custom_fields(who, extra["custom_fields"])
    if not (req.status or req.assignee is not None or req.note or req.verdict is not None or extra):
        raise HTTPException(422, "nothing to update")
    cur = _find_incident(inc_id, who)
    if req.status and req.status != cur.get("status"):
        closing = req.status in CLOSED or cur.get("status") in CLOSED  # closing, or re-opening a closed case
        need(who, "cases.close" if closing else "cases.update")
    if req.assignee is not None and req.assignee != (cur.get("assignee") or ""):
        need(who, "cases.update" if who.named and req.assignee in (who.name, "") and cur.get("assignee") in (None, who.name)
             else "cases.assign")
    if req.note or req.verdict is not None or extra:
        need(who, "cases.update")
    name = actor(who, req.analyst)
    inc = E(who).update_incident(inc_id, name, req.status, req.assignee, req.note, verdict=req.verdict, **extra)
    if inc is None:
        raise HTTPException(404, "incident not found")
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=name, module="soc.incident", target=f"incident:{inc_id}",
                 purpose=req.note or f"status={req.status} assignee={req.assignee}", legal_basis="own_asset",
                 case_ref=f"INC-{inc_id}", result={k: v for k, v in req.model_dump().items() if v is not None})
    return inc


# ---------- cases (incidents as cases: list, manual creation, custom fields, assets) ----------
PRIO = ["low", "medium", "high", "critical"]


def _case_row(i: dict) -> dict:
    upd = max([h.get("ts", 0) for h in i.get("history", [])] + [n.get("ts", 0) for n in i.get("notes", [])] + [i.get("last_ts", 0)])
    sev = i.get("severity", "info")
    return {"id": i["id"], "name": i.get("name") or i.get("title"), "status": i.get("status"),
            "priority": i.get("priority") or (sev if sev in PRIO else "low"), "verdict": i.get("verdict"),
            "tags": i.get("tags", []), "custom_fields": i.get("custom_fields", {}), "assignee": i.get("assignee"),
            "type": i.get("type", "automatic"), "real": bool(i.get("real")), "alerts": len(i.get("alerts", [])),
            "hosts": i.get("hosts", [])[:8], "first_ts": i.get("first_ts"), "last_ts": i.get("last_ts"),
            "updated_ts": upd, "severity": sev, "coordinated": i.get("coordinated", False)}


@app.get("/api/soc/cases")
async def soc_cases(status: str = "", priority: str = "", q: str = "", tag: str = "", assignee: str = "",
                    type: str = "", real_only: bool = False, sort: str = "updated", page: int = 1, size: int = 25,
                    who: rbac.Principal = Depends(require("cases.read"))):
    merged = {i["id"]: i for i in soc_store.incidents(None, 2000 * settings.soc_scale, who.tenant)}
    merged.update(E(who).incidents)
    rows = [_case_row(i) for i in merged.values()]
    if status:
        rows = [r for r in rows if r["status"] in status.split(",")]
    if priority:
        rows = [r for r in rows if r["priority"] in priority.split(",")]
    if tag:
        rows = [r for r in rows if tag.lower() in (t.lower() for t in r["tags"])]
    if assignee:
        rows = [r for r in rows if (r["assignee"] or "") == (who.name if assignee == "me" else assignee)]
    if type:
        rows = [r for r in rows if r["type"] == type]
    if real_only:
        rows = [r for r in rows if r["real"]]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in f"{r['name']} {' '.join(r['hosts'])} {' '.join(r['tags'])} {r['id']}".lower()]
    keys = {"updated": lambda r: -r["updated_ts"], "created": lambda r: -(r["first_ts"] or 0),
            "priority": lambda r: (-PRIO.index(r["priority"]), -r["updated_ts"])}
    rows.sort(key=keys.get(sort, keys["updated"]))
    size = max(5, min(size, 100))
    pages = max(1, -(-len(rows) // size))
    page = max(1, min(page, pages))
    tags = sorted({t for r in rows for t in r["tags"]})
    return {"total": len(rows), "page": page, "pages": pages, "items": rows[(page - 1) * size: page * size],
            "tags": tags, "fields": soc_store.get_setting("case_fields", [], who.tenant)}


class CaseIn(BaseModel):
    template_id: int | None = None
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=8000)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    assignee: str | None = Field(default=None, max_length=80)
    tags: list[str] = Field(default_factory=list, max_length=30)
    hosts: list[str] = Field(default_factory=list, max_length=50)
    custom_fields: dict[str, str | int | float | None] = Field(default_factory=dict)


@app.post("/api/soc/cases")
async def soc_case_create(req: CaseIn, who: rbac.Principal = Depends(require("cases.create"))):
    tpl = None
    if req.template_id is not None:
        tpl = next((t for t in soc_store.get_setting("case_templates", [], who.tenant) if t["id"] == req.template_id), None)
        if tpl is None:
            raise HTTPException(422, "unknown case template")
    inc = E(who).create_case(who.name, req.name.strip(), req.description, req.priority, _check_assignee(who, req.assignee),
                             _clean_tags(req.tags + (tpl["tags"] if tpl else [])), [h.strip()[:255] for h in req.hosts if h.strip()],
                             _check_custom_fields(who, req.custom_fields))
    if tpl:
        now = time.time()
        inc["template"] = tpl["name"]
        for name in tpl["tasks"]:
            soc_store.save_task({"id": None, "name": name, "description": f"จาก template: {tpl['name']}", "assignee": inc.get("assignee"),
                                 "status": "pending", "due": None, "incident_id": inc["id"], "created_by": who.name,
                                 "created_at": now, "updated_at": now, "history": [], "notes": []}, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.case", target=f"incident:{inc['id']}",
                 purpose=f"create case: {inc['name'][:120]}", legal_basis="own_asset", case_ref=f"INC-{inc['id']}",
                 result={"priority": req.priority})
    return inc


class CaseField(BaseModel):
    key: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    label: str = Field(min_length=1, max_length=60)
    type: Literal["text", "number", "select"] = "text"
    options: list[str] = Field(default_factory=list, max_length=30)


def _check_custom_fields(who: rbac.Principal, values: dict | None) -> dict | None:
    if values is None:
        return None
    defs = {f["key"]: f for f in soc_store.get_setting("case_fields", [], who.tenant)}
    out = {}
    for k, v in values.items():
        f = defs.get(k)
        if f is None:
            raise HTTPException(422, f"unknown custom field '{k}'")
        if v in (None, ""):
            continue
        if f["type"] == "number":
            try:
                v = float(v)
            except (TypeError, ValueError):
                raise HTTPException(422, f"'{f['label']}' must be a number") from None
        elif f["type"] == "select" and str(v) not in f["options"]:
            raise HTTPException(422, f"'{f['label']}' must be one of {', '.join(f['options'])}")
        out[k] = v if f["type"] == "number" else str(v)[:500]
    return out


@app.get("/api/soc/case-fields")
async def soc_case_fields(who: rbac.Principal = Depends(require("cases.read"))):
    return {"fields": soc_store.get_setting("case_fields", [], who.tenant)}


@app.put("/api/soc/case-fields")
async def soc_case_fields_set(fields: list[CaseField], who: rbac.Principal = Depends(require("governance.manage"))):
    if len(fields) > 20 or len({f.key for f in fields}) != len(fields):
        raise HTTPException(422, "at most 20 fields with unique keys")
    data = [f.model_dump() for f in fields]
    soc_store.set_setting("case_fields", data, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.case_fields", target="case_fields",
                 purpose=", ".join(f["key"] for f in data) or "cleared", legal_basis="own_asset", case_ref=None, result={})
    return {"fields": data}


@app.get("/api/soc/assets/criticality")
async def soc_assets(who: rbac.Principal = Depends(require("assets.read"))):
    return {"criticality": soc_store.get_setting("asset_criticality", {}, who.tenant)}


class Criticality(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    level: int = Field(ge=0, le=5)


@app.put("/api/soc/assets/criticality")
async def soc_asset_set(req: Criticality, who: rbac.Principal = Depends(require("assets.manage"))):
    cur = soc_store.get_setting("asset_criticality", {}, who.tenant)
    if req.level == 0:
        cur.pop(req.host, None)
    else:
        cur[req.host] = req.level
    if len(cur) > 5000 * settings.soc_scale:
        raise HTTPException(413, "too many assets")
    soc_store.set_setting("asset_criticality", cur, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.asset", target=f"host:{req.host}",
                 purpose=f"criticality={req.level}", legal_basis="own_asset", case_ref=None, result={})
    return {"host": req.host, "level": req.level}


@app.get("/api/soc/cases/{inc_id}/events")
async def soc_case_events(inc_id: int, q: str = "", who: rbac.Principal = Depends(require("events.read"))):
    """Raw telemetry for the case's hosts and users, from 1 h before first seen to 1 h after last seen."""
    inc = _find_incident(inc_id, who)
    start, end = (inc.get("first_ts") or time.time()) - 3600, min(time.time(), (inc.get("last_ts") or time.time()) + 3600)
    hosts = {h.lower() for h in inc.get("hosts", []) if h}
    users = {u.lower() for u in inc.get("users", []) if u and u not in ("unknown", "-")}
    eng = E(who)
    recs = [r for r in eng.raw if start <= (r.get("ts") or 0) <= end and not (eng.persist and r.get("simulated") is False)]
    if eng.persist:
        recs += soc_store.raw_between(start, end, who.tenant)

    def related(r):
        vals = {str(r.get(k) or "").lower() for k in ("host", "dest_host", "src_host", "dst_host", "client_host", "user")}
        return bool(vals & (hosts | users))
    out = explorer.explore([r for r in recs if related(r)], q[:300], start, end, limit=300)
    return {**out, "start": start, "end": end, "hosts": sorted(hosts), "users": sorted(users)}


# ---------- rules catalog ----------
@app.get("/api/soc/rules/catalog")
async def soc_rules_catalog(who: rbac.Principal = Depends(require("rules.read"))):
    now = time.time()
    events = _tenant_events(who, now - 7 * 86400, now)
    incs = dict(E(who).incidents)
    for i in soc_store.incidents(None, 2000 * settings.soc_scale, who.tenant):
        incs.setdefault(i["id"], i)
    out = catalog.catalog(soc_store.list_rules(who.tenant), E(who).disabled_rules, events, incs, now)
    out["suppressed_since_start"] = dict(E(who).suppressed)
    out["configured_sources"] = sorted({k.split(" · ")[-1] for k in soc_store.counts(who.tenant) if k.startswith("src:")}
                                       | {k.split(" · ")[-1] for k in E(who).sources if "(จำลอง)" not in k})
    out["active_iocs"] = {n: len(threatintel.feed_index(n)) for n in ("threatfox", "feodo", "kev")}
    out["active_iocs"]["agentic"] = len(threatintel.agentic_index())
    return out


class RuleToggle(BaseModel):
    enabled: bool


@app.put("/api/soc/rules/{rule_id}/enabled")
async def soc_rule_toggle(rule_id: str, req: RuleToggle, who: rbac.Principal = Depends(require("rules.publish"))):
    known = {r["id"] for r in catalog.builtin_rules()} | {r["id"] for r in soc_store.list_rules(who.tenant)}
    if rule_id not in known:
        raise HTTPException(404, "rule not found")
    eng = E(who)
    (eng.disabled_rules.discard if req.enabled else eng.disabled_rules.add)(rule_id)
    soc_store.set_setting("disabled_rules", sorted(eng.disabled_rules), who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.rule_toggle", target=f"rule:{rule_id}",
                 purpose=f"enabled={req.enabled}", legal_basis="own_asset", case_ref=None, result={})
    return {"id": rule_id, "enabled": req.enabled}


# ---------- query builder ----------
class QueryIn(BaseModel):
    query: str = Field(min_length=1, max_length=4000)
    minutes: int = Field(default=60, ge=1, le=7 * 24 * 60)


@app.post("/api/soc/query")
async def soc_query(req: QueryIn, who: rbac.Principal = Depends(require("query.run"))):
    try:
        plan = query.parse(req.query)
    except query.QueryError as e:
        raise HTTPException(422, str(e)) from e
    end = time.time()
    start = end - req.minutes * 60
    t0 = time.perf_counter()
    if plan["source"] == "alerts":
        rows = sorted(_tenant_events(who, start, end), key=lambda e: -e["ts"])
    else:
        eng = E(who)
        rows = [r for r in eng.raw if start <= (r.get("ts") or 0) <= end and not (eng.persist and r.get("simulated") is False)]
        if eng.persist:
            rows += soc_store.raw_between(start, end, who.tenant)
        rows = sorted(({**{k: v for k, v in r.items() if not k.startswith("_")}, "source": r.get("_source"),
                        "description": explorer.describe(r)} for r in rows), key=lambda r: -(r.get("ts") or 0))
    out = query.run(plan, rows)
    return {**out, "scanned": len(rows), "start": start, "end": end, "source": plan["source"],
            "duration_ms": round((time.perf_counter() - t0) * 1000, 1)}


class SavedQuery(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    query: str = Field(min_length=1, max_length=4000)
    minutes: int = Field(default=60, ge=1, le=7 * 24 * 60)


@app.get("/api/soc/queries")
async def soc_saved_queries(who: rbac.Principal = Depends(require("query.run"))):
    return {"queries": soc_store.get_setting("saved_queries", [], who.tenant)}


@app.post("/api/soc/queries")
async def soc_save_query(req: SavedQuery, who: rbac.Principal = Depends(require("query.run"))):
    try:
        query.parse(req.query)
    except query.QueryError as e:
        raise HTTPException(422, str(e)) from e
    cur = soc_store.get_setting("saved_queries", [], who.tenant)
    if len(cur) >= 200:
        raise HTTPException(413, "too many saved queries")
    item = {**req.model_dump(), "id": max([q["id"] for q in cur] + [0]) + 1, "by": who.name, "ts": time.time()}
    soc_store.set_setting("saved_queries", cur + [item], who.tenant)
    return item


@app.delete("/api/soc/queries/{qid}")
async def soc_delete_query(qid: int, who: rbac.Principal = Depends(require("query.run"))):
    cur = soc_store.get_setting("saved_queries", [], who.tenant)
    new = [q for q in cur if q["id"] != qid]
    if len(new) == len(cur):
        raise HTTPException(404, "query not found")
    soc_store.set_setting("saved_queries", new, who.tenant)
    return {"deleted": qid}


# ---------- notebooks ----------
class NotebookIn(BaseModel):
    title: str = Field(default="Untitled", min_length=1, max_length=200)
    content: str = Field(default="", max_length=200_000)
    case_id: int | None = None


@app.get("/api/soc/notebooks")
async def soc_notebooks(trash: bool = False, q: str = "", case_id: int | None = None,
                        who: rbac.Principal = Depends(require("notebooks.read"))):
    items = soc_store.notebooks(who.tenant, deleted=trash)
    if case_id is not None:
        items = [n for n in items if n.get("case_id") == case_id]
    if q:
        items = [n for n in items if q.lower() in (n["title"] + " " + n["content"]).lower()]
    return {"notebooks": items}


@app.post("/api/soc/notebooks")
async def soc_notebook_create(req: NotebookIn, who: rbac.Principal = Depends(require("notebooks.write"))):
    if req.case_id is not None:
        _find_incident(req.case_id, who)
    now = time.time()
    nb = soc_store.save_notebook({"id": None, **req.model_dump(), "created_by": who.name, "created_at": now,
                                  "updated_by": who.name, "updated_at": now, "deleted": False}, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.notebook", target=f"notebook:{nb['id']}",
                 purpose=f"create: {nb['title'][:120]}", legal_basis="own_asset",
                 case_ref=f"INC-{req.case_id}" if req.case_id else None, result={})
    return nb


class NotebookPatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    content: str | None = Field(default=None, max_length=200_000)
    deleted: bool | None = None
    base_updated_at: float | None = None  # optimistic concurrency: reject if someone saved in between


@app.put("/api/soc/notebooks/{nb_id}")
async def soc_notebook_update(nb_id: int, req: NotebookPatch, who: rbac.Principal = Depends(require("notebooks.write"))):
    nb = soc_store.notebook(nb_id, who.tenant)
    if nb is None:
        raise HTTPException(404, "notebook not found")
    if req.base_updated_at is not None and abs(req.base_updated_at - nb["updated_at"]) > 1e-6:
        raise HTTPException(409, f"notebook was changed by {nb['updated_by']} — reload before saving")
    for k in ("title", "content", "deleted"):
        if getattr(req, k) is not None:
            nb[k] = getattr(req, k)
    nb.update(updated_by=who.name, updated_at=time.time())
    soc_store.save_notebook(nb, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.notebook", target=f"notebook:{nb_id}",
                 purpose="trash" if req.deleted else "restore" if req.deleted is False else "edit", legal_basis="own_asset",
                 case_ref=f"INC-{nb['case_id']}" if nb.get("case_id") else None, result={})
    return nb


# ---------- analyst workspace: overview widgets, tasks, notifications ----------
@app.get("/api/soc/overview")
async def soc_overview(who: rbac.Principal = Depends(require("soc.read"))):
    """Homepage widgets: pending alerts, opened cases, alert list with occurrences + urgency, events by data source,
    top observed threats (24 h) and task counts. Computed from the tenant's live window plus persisted counters."""
    eng = E(who)
    now = time.time()
    events = list(eng.events)
    alerts = workspace.alert_summary(events, eng.incidents, states=_alert_states(who.tenant))
    tasks = _all_tasks(who)
    hist = _tenant_events(who, now - 2 * 86400, now)
    cur_a = sum(1 for e in hist if e["ts"] >= now - 86400 and e.get("severity") not in ("info", "low"))
    prev_a = sum(1 for e in hist if e["ts"] < now - 86400 and e.get("severity") not in ("info", "low"))
    merged = {i["id"]: i for i in soc_store.incidents(None, 500 * settings.soc_scale, who.tenant)}
    merged.update(eng.incidents)
    cur_c = sum(1 for i in merged.values() if (i.get("first_ts") or 0) >= now - 86400)
    prev_c = sum(1 for i in merged.values() if now - 2 * 86400 <= (i.get("first_ts") or 0) < now - 86400)
    trend = lambda c, p: None if p == 0 else round(100 * (c - p) / p)  # noqa: E731
    comments = sorted(({"incident_id": i["id"], "title": i.get("name") or i.get("title"), **n}
                       for i in merged.values() for n in i.get("notes", [])), key=lambda n: -n["ts"])[:8]
    recent_cases = [_case_row(i) for i in sorted(merged.values(), key=lambda i: -(i.get("first_ts") or 0))[:6]]
    return {"pending_alerts": sum(1 for a in alerts if a["status"] in ("new", "open")),
            "ongoing_alerts": sum(1 for a in alerts if a["status"] in ("investigating", "acknowledged", "escalated")),
            "trend": {"alerts_24h": cur_a, "alerts_prev_24h": prev_a, "alerts_pct": trend(cur_a, prev_a),
                      "cases_24h": cur_c, "cases_prev_24h": prev_c, "cases_pct": trend(cur_c, prev_c)},
            "last_comments": comments, "recent_cases": recent_cases,
            "opened_cases": sum(1 for i in eng.incidents.values() if i["status"] in ("open", "investigating")),
            "alerts": alerts, "data_sources": workspace.data_sources(eng.sources),
            "events_total": sum(eng.sources.values()), "top_threats": workspace.top_threats(events, now - 86400),
            "tasks": workspace.by_status(tasks), "simulated": eng.simulate,
            "urgency_formula": "severity base (critical 85 / high 70 / medium 45 / low 20) + occurrences-1 (max 10) "
                               "+ 5 CTI match + 5 coordinated multi-domain incident, capped at 100"}


class TaskIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=8000)
    assignee: str | None = Field(default=None, max_length=80)
    status: Literal[workspace.TASK_STATUSES] = "pending"  # type: ignore[valid-type]
    due: float | None = None  # epoch seconds
    incident_id: int | None = None


class TaskPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=8000)
    assignee: str | None = Field(default=None, max_length=80)  # "" clears
    status: Literal[workspace.TASK_STATUSES] | None = None  # type: ignore[valid-type]
    due: float | None = None
    clear_due: bool = False
    note: str | None = Field(default=None, max_length=4000)


def _assignees(who: rbac.Principal) -> list[str]:
    return [u["username"] for u in rbac.list_users(who.tenant) if not u["disabled"] and u["role"] != "ingest"]


def _check_assignee(who: rbac.Principal, name: str | None) -> str | None:
    if not name:
        return None
    known = _assignees(who)
    if known and name not in known and name != who.name:
        raise HTTPException(422, f"assignee '{name}' is not an active user of tenant {who.tenant}")
    return name


@app.get("/api/soc/assignees")
async def soc_assignees(who: rbac.Principal = Depends(require("soc.read"))):
    names = _assignees(who)
    if who.named and who.name not in names:
        names.append(who.name)
    return {"users": sorted(names), "me": who.name if who.named else None}


def _all_tasks(who: rbac.Principal) -> list[dict]:
    """Stored tasks plus the demo team's tasks in a simulated tenant (marked simulated, read-only)."""
    return soc_store.list_tasks(who.tenant) + demo_tasks.sync(E(who), time.time())


@app.get("/api/soc/tasks")
async def soc_tasks(status: str | None = None, q: str | None = None, assignee: str | None = None,
                    who: rbac.Principal = Depends(require("soc.read"))):
    every = _all_tasks(who)
    items = list(every)
    if status:
        items = [t for t in items if t["status"] in status.split(",")]
    if assignee:
        items = [t for t in items if t.get("assignee") == assignee]
    if q:
        ql = q.lower()
        items = [t for t in items if ql in t["name"].lower() or ql in (t.get("description") or "").lower()]
    return {"tasks": items, "by_status": workspace.by_status(every),
            "statuses": [{"id": s, "th": workspace.TASK_TH[s]} for s in workspace.TASK_STATUSES]}


@app.post("/api/soc/tasks")
async def soc_task_create(req: TaskIn, who: rbac.Principal = Depends(require("cases.update"))):
    if req.assignee and req.assignee != who.name:
        need(who, "cases.assign")
    if req.incident_id is not None:
        _find_incident(req.incident_id, who)
    now = time.time()
    t = soc_store.save_task({"id": None, "name": req.name.strip(), "description": req.description,
                             "assignee": _check_assignee(who, req.assignee), "status": req.status, "due": req.due,
                             "incident_id": req.incident_id, "created_by": who.name, "created_at": now,
                             "updated_at": now, "history": [], "notes": []}, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.task", target=f"task:{t['id']}",
                 purpose=f"create: {t['name'][:120]}", legal_basis="own_asset",
                 case_ref=f"INC-{req.incident_id}" if req.incident_id else None,
                 result={"status": t["status"], "assignee": t["assignee"]})
    return t


@app.patch("/api/soc/tasks/{task_id}")
async def soc_task_update(task_id: int, req: TaskPatch, who: rbac.Principal = Depends(require("cases.update"))):
    if task_id < 0:
        raise HTTPException(409, "งานจำลอง (demo) แก้ไขไม่ได้ — สร้างงานจริงด้วย + สร้างงาน")
    t = soc_store.task(task_id, who.tenant)
    if t is None:
        raise HTTPException(404, "task not found")
    now = time.time()
    changes = []
    if req.name is not None and req.name.strip() != t["name"]:
        t["name"] = req.name.strip()
        changes.append("name")
    if req.description is not None and req.description != t.get("description"):
        t["description"] = req.description
        changes.append("description")
    if req.assignee is not None and (req.assignee or None) != t.get("assignee"):
        if not (who.named and req.assignee in (who.name, "") and t.get("assignee") in (None, who.name)):
            need(who, "cases.assign")  # taking a free task yourself only needs cases.update
        t["assignee"] = _check_assignee(who, req.assignee)
        changes.append(f"assignee → {t['assignee'] or '-'}")
    if req.status and req.status != t["status"]:
        changes.append(f"status {t['status']} → {req.status}")
        t["status"] = req.status
        if req.status == "completed":
            t["completed_at"] = now
    if req.clear_due or (req.due is not None and req.due != t.get("due")):
        t["due"] = None if req.clear_due else req.due
        changes.append("due")
    if req.note:
        t.setdefault("notes", []).append({"ts": now, "analyst": who.name, "text": req.note})
        changes.append("note")
    if not changes:
        raise HTTPException(422, "nothing to update")
    t.setdefault("history", []).append({"ts": now, "analyst": who.name, "change": ", ".join(changes)})
    t["updated_at"] = now
    soc_store.save_task(t, who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.task", target=f"task:{task_id}",
                 purpose=req.note or ", ".join(changes), legal_basis="own_asset",
                 case_ref=f"INC-{t['incident_id']}" if t.get("incident_id") else None,
                 result={k: v for k, v in req.model_dump().items() if v not in (None, False)})
    return t


@app.get("/api/soc/notifications")
async def soc_notifications(who: rbac.Principal = Depends(require("soc.read"))):
    """What needs the caller's attention: their open tasks (overdue first) and incidents assigned to them, plus
    unassigned critical incidents from the last 24 h."""
    incs = list(E(who).incidents.values())
    items = workspace.notifications(who.name, soc_store.list_tasks(who.tenant), incs, time.time())
    inbox = soc_store.inbox(who.name, who.tenant, 30)
    return {"items": items, "urgent": sum(1 for n in items if n["urgent"]), "inbox": inbox,
            "unread": sum(1 for n in inbox if not n["read"])}


class InboxRead(BaseModel):
    ids: list[int] | None = Field(default=None, max_length=500)  # None = all


@app.post("/api/soc/notifications/read")
async def soc_notifications_read(req: InboxRead, who: rbac.Principal = Depends(require("soc.read"))):
    return {"marked": soc_store.mark_inbox_read(who.name, who.tenant, req.ids)}


# ---------- notification rules (the "notification creation tool") ----------
class NotifyRule(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    min_urgency: int = Field(default=0, ge=0, le=100)
    domains: list[Literal["endpoint", "identity", "email", "network", "cloud", "data", "agent"]] = Field(default_factory=list)
    rule_prefixes: list[str] = Field(default_factory=list, max_length=20)
    keyword: str = Field(default="", max_length=120)
    real_only: bool = True
    channels: list[Literal["in_app", "teams", "line", "slack", "webhook", "email"]] = Field(default_factory=lambda: ["in_app"])


@app.get("/api/soc/notify-rules")
async def soc_notify_rules(who: rbac.Principal = Depends(require("soc.read"))):
    return {"rules": notify_rules.rules(who.tenant), "server_channels": notifier.channels(),
            "channels": list(notify_rules.CHANNELS)}


@app.post("/api/soc/notify-rules/test")
async def soc_notify_rule_test(req: NotifyRule, who: rbac.Principal = Depends(require("integrations.manage"))):
    return {"matches": notify_rules.test_rule(req.model_dump(), list(E(who).incidents.values()))}


@app.post("/api/soc/notify-rules")
async def soc_notify_rule_create(req: NotifyRule, who: rbac.Principal = Depends(require("integrations.manage"))):
    rule = req.model_dump()
    errs = notify_rules.validate(rule)
    if errs:
        raise HTTPException(422, "; ".join(errs))
    rule = soc_store.save_notify_rule({**rule, "id": None, "created_by": who.name, "created_at": time.time()}, who.tenant)
    notify_rules.invalidate(who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.notify_rule", target=f"notify_rule:{rule['id']}",
                 purpose=f"create: {rule['name']}", legal_basis="own_asset", case_ref=None,
                 result={k: rule[k] for k in ("min_severity", "min_urgency", "channels", "real_only")})
    return rule


@app.put("/api/soc/notify-rules/{rule_id}")
async def soc_notify_rule_update(rule_id: int, req: NotifyRule, who: rbac.Principal = Depends(require("integrations.manage"))):
    old = next((r for r in notify_rules.rules(who.tenant) if r["id"] == rule_id), None)
    if old is None:
        raise HTTPException(404, "rule not found")
    rule = {**old, **req.model_dump(), "id": rule_id, "updated_by": who.name, "updated_at": time.time()}
    errs = notify_rules.validate(rule)
    if errs:
        raise HTTPException(422, "; ".join(errs))
    soc_store.save_notify_rule(rule, who.tenant)
    notify_rules.invalidate(who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.notify_rule", target=f"notify_rule:{rule_id}",
                 purpose=f"update: {rule['name']} enabled={rule['enabled']}", legal_basis="own_asset", case_ref=None,
                 result={k: rule[k] for k in ("min_severity", "min_urgency", "channels", "real_only", "enabled")})
    return rule


@app.delete("/api/soc/notify-rules/{rule_id}")
async def soc_notify_rule_delete(rule_id: int, who: rbac.Principal = Depends(require("integrations.manage"))):
    if not soc_store.delete_notify_rule(rule_id, who.tenant):
        raise HTTPException(404, "rule not found")
    notify_rules.invalidate(who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.notify_rule", target=f"notify_rule:{rule_id}",
                 purpose="delete", legal_basis="own_asset", case_ref=None, result={})
    return {"deleted": rule_id}


# ---------- threat landscape, events explorer, alerts list ----------
def _tenant_events(who: rbac.Principal, start: float, end: float) -> list[dict]:
    """Alert events in a window: persisted real ones from the database plus the in-memory (simulated) window."""
    seen, out = set(), []
    for e in soc_store.events_between(start, end, who.tenant) + list(E(who).events):
        if start <= e["ts"] <= end and (e["id"], e.get("simulated")) not in seen:
            seen.add((e["id"], e.get("simulated")))
            out.append(e)
    return out


@app.get("/api/soc/threatmap")
async def soc_threatmap(days: int = 7, who: rbac.Principal = Depends(require("alerts.read"))):
    """Threat Map: origin country of the infrastructure behind this tenant's alerts (event src_country or Feodo C2
    country — never guessed), attack trend, most-hit assets, MITRE tactic share, Feodo C2 hosting countries."""
    days = max(1, min(days, 30))
    now = time.time()
    eng = E(who)
    merged = {i["id"]: i for i in soc_store.incidents(None, 500 * settings.soc_scale, who.tenant)}
    merged.update(eng.incidents)
    out = threatmap.build(_tenant_events(who, now - 30 * 86400, now), list(merged.values()),
                          threatintel.feed_index("feodo"), _indicators(who.tenant), settings.soc_home_country, now, days)
    return {**out, "simulated": eng.simulate}


@app.get("/api/soc/landscape")
async def soc_landscape(hours: int = 24, who: rbac.Principal = Depends(require("alerts.read"))):
    hours = max(1, min(hours, 24 * 30))
    now = time.time()
    tf, kev = threatintel.feed_index("threatfox"), threatintel.feed_index("kev")
    events = _tenant_events(who, now - max(hours, 7 * 24) * 3600, now)
    return {"malware_trend": landscape.malware_trend(tf), "kev_trend": landscape.kev_trend(kev),
            "latest_kev": landscape.latest_kev(kev),
            "technique_trend": landscape.technique_trend(events, now, hours, 12 if hours <= 48 else min(30, hours // 24)),
            "threats": landscape.threats_table(events, now, tf, kev), "hours": hours,
            "feeds_loaded": {"threatfox": bool(tf), "kev": bool(kev)}, "simulated": E(who).simulate}


@app.get("/api/soc/events")
async def soc_events(q: str = "", minutes: int = 15, end: float | None = None, limit: int = 200,
                     who: rbac.Principal = Depends(require("events.read"))):
    """Raw telemetry explorer: real records from the database (kept SOC_RAW_RETENTION_DAYS) plus the in-memory window."""
    minutes = max(1, min(minutes, 7 * 24 * 60))
    end = min(end or time.time(), time.time())
    start = end - minutes * 60
    eng = E(who)
    mem = [r for r in eng.raw if start <= (r.get("ts") or 0) <= end]
    real_mem = {id(r) for r in mem if r.get("simulated") is False}
    records = [r for r in mem if id(r) not in real_mem] if eng.persist else mem
    if eng.persist:
        records += soc_store.raw_between(start, end, who.tenant)
    out = explorer.explore(records, q[:300], start, end, limit=min(max(limit, 1), 1000))
    return {**out, "start": start, "end": end, "query": q[:300],
            "retention_days": soc_store.RAW_RETENTION_DAYS, "memory_window": eng.raw.maxlen}


@app.get("/api/soc/alerts")
async def soc_alerts(status: str = "", severity: str = "", q: str = "", real_only: bool = False, sort: str = "recent",
                     page: int = 1, size: int = 25, hours: int = 24, who: rbac.Principal = Depends(require("alerts.read"))):
    now = time.time()
    events = _tenant_events(who, now - max(1, min(hours, 24 * 90)) * 3600, now)
    incs = dict(E(who).incidents)
    for e in events:  # older persisted incidents that are no longer in memory
        iid = e.get("incident_id")
        if iid and iid not in incs and e.get("simulated") is False:
            inc = soc_store.incident(iid, who.tenant)
            if inc:
                incs[iid] = inc
    return explorer.alerts_page(events, incs, status, severity, q[:200], real_only, sort, page, size,
                                states=_alert_states(who.tenant))


def _find_incident(inc_id: int, who: rbac.Principal) -> dict:
    inc = E(who).incidents.get(inc_id) or soc_store.incident(inc_id, who.tenant)
    if inc is None:
        raise HTTPException(404, "incident not found")
    return inc


@app.get("/api/soc/incidents")
async def soc_incidents(status: str | None = None, real_only: bool = True, limit: int = 200,
                        who: rbac.Principal = Depends(require("cases.read"))):
    """Incident list. real_only (default) reads persisted cases from SQLite; otherwise the live in-memory set."""
    limit = min(max(limit, 1), 1000)
    if real_only:
        return soc_store.incidents(status, limit, who.tenant)
    items = sorted(E(who).incidents.values(), key=lambda i: -i["last_ts"])
    return [i for i in items if not status or i["status"] == status][:limit]


@app.get("/api/soc/incidents/{inc_id}")
async def soc_incident(inc_id: int, who: rbac.Principal = Depends(require("cases.read"))):
    return _find_incident(inc_id, who)


@app.get("/api/soc/incidents/{inc_id}/report", response_class=HTMLResponse)
async def soc_incident_report(inc_id: int, analyst: str = "", who: rbac.Principal = Depends(require("soc.export"))):
    html = soc_report.html_report(_find_incident(inc_id, who), who.name if who.named else analyst[:80])
    return HTMLResponse(html, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                                  "script-src 'unsafe-inline'"})


@app.get("/api/soc/incidents.csv")
async def soc_incidents_csv(status: str | None = None, real_only: bool = True, who: rbac.Principal = Depends(require("soc.export"))):
    items = await soc_incidents(status, real_only, 1000, who)
    return Response(soc_report.csv_export(items), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="soc-incidents.csv"'})


@app.post("/api/soc/agents/{agent_id}/contain")
async def soc_contain(agent_id: str, req: ContainRequest, who: rbac.Principal = Depends(require("respond.execute"))):
    """Response action: revoke the agent's token / suspend it (simulated). With the four-eyes policy (default) this
    only files a request; a different person with respond.approve executes it."""
    if agent_id not in E(who).agents.agents:
        raise HTTPException(404, "unknown agent")
    action = "contain" if req.contain else "release"
    if _policies(who.tenant)["four_eyes_response"]:
        r = _new_request(who, "response_requests", {"action": action, "agent": agent_id, "reason": req.reason,
                                                    "requested_by_display": actor(who, req.analyst)})
        audit.record(tenant=who.tenant, client_ip=who.ip, analyst=actor(who, req.analyst), module="soc.response_request",
                     target=agent_id, purpose=f"{action}: {req.reason}", legal_basis="own_asset", case_ref=None,
                     result={"request_id": r["id"], "status": "pending"})
        return JSONResponse({"status": "pending_approval", "request": r,
                             "note": "ต้องให้ผู้มีสิทธิ์ respond.approve คนอื่นอนุมัติก่อนจึงจะดำเนินการ"}, status_code=202)
    result = _do_contain(who, agent_id, req.contain)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=actor(who, req.analyst), module="soc.contain" if req.contain else "soc.release",
                 target=agent_id, purpose=req.reason, legal_basis="own_asset", case_ref=None,
                 result={"contained": req.contain, "simulated": True, "four_eyes": False})
    return result


def sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


async def soc_events(request: Request, q: asyncio.Queue, tenant: str):
    try:
        yield sse("snapshot", hub.engine_for(tenant).snapshot())
        while not await request.is_disconnected():
            try:
                msg = await asyncio.wait_for(q.get(), timeout=15)
                yield sse("tick", msg)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
    finally:
        hub.unsubscribe(q)


@app.get("/api/soc/stream")
async def soc_stream(request: Request, who: rbac.Principal = Depends(require("soc.read"))):
    """Server-Sent Events. Read with fetch() so the X-API-Key header can be sent."""
    return StreamingResponse(soc_events(request, hub.subscribe(who.tenant), who.tenant), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/soc")
def soc_page():
    return FileResponse(STATIC / "soc.html")


MANUAL = Path(__file__).resolve().parent.parent / "docs" / "USER_MANUAL.md"


@app.get("/manual")
def manual_page():
    """The user manual (rendered in the browser from /manual.md)."""
    return FileResponse(STATIC / "manual.html")


@app.get("/manual.md")
def manual_md():
    return FileResponse(MANUAL, media_type="text/markdown; charset=utf-8")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
