"""OSINT Toolkit — FastAPI entry point."""
import asyncio
import csv
import hmac
import io
import os
import tempfile
import json
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from starlette.background import BackgroundTask
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import audit, rbac
from app import ai, explorer, ingest, landscape, notify_rules, phase3, phase4, soc_report, soc_store, workspace
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
        return _with_tenant(rbac.Principal("admin (bootstrap key)", "admin", client, False, set(rbac.ROLES["admin"]),
                                           platform=True), request)
    user = rbac.authenticate(x_api_key, client)
    if user:
        return _with_tenant(user, request)
    if not settings.api_key and not rbac.has_users():  # local development: no credentials configured at all
        return _with_tenant(rbac.Principal("anonymous", "admin", client, False, set(rbac.ROLES["admin"]),
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
        "integrations": {"hibp": bool(settings.hibp_api_key), "ipinfo": bool(settings.ipinfo_token)},
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


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=63)
    tenant: str | None = Field(default=None, max_length=41)  # platform staff only; "*" = platform user
    role: Literal["viewer", "analyst", "lead", "admin", "ingest"]


class UserUpdate(BaseModel):
    role: Literal["viewer", "analyst", "lead", "admin", "ingest"] | None = None
    disabled: bool | None = None


@app.get("/api/users")
def users_list(who: rbac.Principal = Depends(require("users.manage"))):
    return {"users": rbac.list_users(None if who.platform else who.tenant), "roles": [{"id": r, "th": rbac.ROLE_TH[r], "permissions": sorted(p)}
                                                  for r, p in rbac.ROLES.items()]}


@app.post("/api/users")
def users_create(req: UserCreate, who: rbac.Principal = Depends(require("users.manage"))):
    try:
        tenant = (req.tenant or who.tenant) if who.platform else who.tenant
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
def users_rotate(username: str, who: rbac.Principal = Depends(require("users.manage"))):
    _same_tenant_user(username, who)
    token = rbac.rotate(username)
    if token is None:
        raise HTTPException(404, "user not found")
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="rbac.rotate", target=username, purpose="rotate token",
                 legal_basis="own_asset", case_ref=None, result={})
    return {"username": username, "token": token}


@app.patch("/api/users/{username}")
def users_update(username: str, req: UserUpdate, who: rbac.Principal = Depends(require("users.manage"))):
    _same_tenant_user(username, who)
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
def tenants_list(who: rbac.Principal = Depends(require("users.manage"))):
    """Platform staff: every tenant known to the system. Others: their own tenant."""
    if not who.platform:
        return {"tenants": [who.tenant], "current": who.tenant}
    names = {"default", *soc_store.tenants(), *rbac.tenants(), *hub.engines}
    return {"tenants": sorted(names), "current": who.tenant}


@app.get("/api/soc/snapshot")
async def soc_snapshot(who: rbac.Principal = Depends(require("soc.read"))):
    return E(who).snapshot()


@app.get("/api/soc/cti")
async def soc_cti(refresh: bool = False, who: rbac.Principal = Depends(require("soc.read"))):
    return threatintel.public(await threatintel.get_all(force=refresh))


@app.get("/api/soc/offensive-ai")
async def soc_offensive_ai(who: rbac.Principal = Depends(require("soc.read"))):
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
async def soc_agents(who: rbac.Principal = Depends(require("soc.read"))):
    m = E(who).agents
    return {"agents": m.inventory(), "rules": m.rules()}


@app.get("/api/soc/agents/sessions/{sid}")
async def soc_agent_session(sid: str, who: rbac.Principal = Depends(require("soc.read"))):
    data = E(who).agents.session(sid[:20])
    if not data:
        raise HTTPException(404, "session not found")
    return data


@app.get("/api/soc/hunt")
async def soc_hunt(q: str = "", limit: int = 100, who: rbac.Principal = Depends(require("soc.read"))):
    return {"query": q[:300], "results": E(who).agents.hunt(q[:300], min(max(limit, 1), 500))}


INGEST_SOURCE = {"auto": "API", "native": "API", "ecs": "Elastic ECS", "defender": "Microsoft Defender",
                 "access_log": "Web access log"}


@app.post("/api/soc/ingest")
async def soc_ingest(request: Request, format: str = "auto", host: str | None = None,
                     who: rbac.Principal = Depends(require("ingest"))):
    """Ingest real EDR / NDR / web / AI-agent telemetry. Formats: auto, native, ecs, defender, access_log."""
    size = request.headers.get("content-length")
    if size and size.isdigit() and int(size) > ingest.MAX_BYTES:
        raise HTTPException(413, f"body larger than {ingest.MAX_BYTES} bytes")
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > ingest.MAX_BYTES:
            raise HTTPException(413, f"body larger than {ingest.MAX_BYTES} bytes")
    try:
        records, rejected = ingest.parse(body, format, host)
    except ingest.IngestError as e:
        raise HTTPException(413 if "larger" in str(e) or "more than" in str(e) else 422, str(e)) from e
    result = E(who).ingest_external(records, source=INGEST_SOURCE.get(format, format))
    if not hub.has_subscribers(who.tenant):  # nobody watching: new viewers get these via the snapshot, so don't re-broadcast later
        E(who).drop_outbox()
    return {**result, "rejected": rejected, "format": format}


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
async def soc_register_agents(items: list[AgentSpec], who: rbac.Principal = Depends(require("agents.manage"))):
    """Upsert real AI agents and what they are allowed to do. Unregistered agents seen in logs raise AGT-011."""
    if len(items) > 500:
        raise HTTPException(413, "max 500 agents per request")
    out = E(who).agents.register([{**a.model_dump(), "account": a.account or a.id} for a in items])
    if E(who).persist:
        soc_store.save_agents([E(who).agents.agents[a["id"]] for a in out], who.tenant)
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
async def soc_notify_test(req: NotifyTest, who: rbac.Principal = Depends(require("notify.test"))):
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
async def soc_ai_summary(inc_id: int, req: AiSummaryRequest, who: rbac.Principal = Depends(require("ai.use"))):
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
async def soc_ai_ask(inc_id: int, req: AiAskRequest, who: rbac.Principal = Depends(require("ai.use"))):
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
async def soc_nl_hunt(req: NlHuntRequest, who: rbac.Principal = Depends(require("ai.use"))):
    out = await phase3.nl_hunt(req.question, _hunt_data(who), time.time())
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ai_hunt", target="hunt", purpose=req.question[:300],
                 legal_basis="own_asset", case_ref=None,
                 result={"mode": out.get("mode"), "total": out.get("total"), "model": out.get("model"), "usage": out.get("usage")})
    return out


class EnrichRequest(BaseModel):
    indicator: str = Field(min_length=3, max_length=500)


@app.post("/api/soc/enrich")
async def soc_enrich(req: EnrichRequest, who: rbac.Principal = Depends(require("ai.use"))):
    out = await phase3.enrich(req.indicator, _hunt_data(who))
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.ai_enrich", target=req.indicator[:200],
                 purpose="threat enrichment", legal_basis="own_asset", case_ref=None,
                 result={"matches": len(out["matches"]), "local_verdict": out["local_verdict"],
                         "ai": bool(out.get("ai")), "usage": (out.get("ai") or {}).get("usage")})
    return out


@app.get("/api/soc/chains")
async def soc_chains(who: rbac.Principal = Depends(require("soc.read"))):
    return {"chains": phase3.build_chains(list(E(who).incidents.values()))[:30]}


@app.post("/api/soc/chains/{chain_id}/ai")
async def soc_chain_ai(chain_id: str, who: rbac.Principal = Depends(require("ai.use"))):
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
def audit_list(limit: int = 200, module: str | None = None, who: rbac.Principal = Depends(require("users.manage"))):
    return {"rows": audit.history(min(max(limit, 1), 2000), tenant=who.tenant, module_prefix=module)}


@app.get("/api/audit/verify")
def audit_verify(who: rbac.Principal = Depends(require("users.manage"))):
    if not who.platform:
        raise HTTPException(403, "chain verification covers every tenant — platform staff only")
    return audit.verify()


@app.get("/api/audit.csv")
def audit_csv(module: str | None = None, who: rbac.Principal = Depends(require("users.manage"))):
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
def ai_feedback(req: Feedback, who: rbac.Principal = Depends(require("ai.use"))):
    """Analyst rating of an AI answer — part of continuous AI evaluation."""
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="ai.feedback", target=f"{req.feature}:{req.ref}",
                 purpose=req.comment or req.rating, legal_basis="own_asset", case_ref=None,
                 result={"feature": req.feature, "rating": req.rating})
    return {"ok": True}


@app.get("/api/governance/ai-usage")
def ai_usage(days: int = 30, who: rbac.Principal = Depends(require("users.manage"))):
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
def admin_backup(who: rbac.Principal = Depends(require("users.manage"))):
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
async def soc_rule_draft(req: RuleDraftRequest, who: rbac.Principal = Depends(require("ai.use"))):
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
async def soc_rule_test(req: RuleTestRequest, who: rbac.Principal = Depends(require("ai.use"))):
    rule = phase4.assemble({"local_rule": req.rule, **{k: v for k, v in req.rule.items() if k != "conditions"}})
    return {"rule": rule, **phase4.evaluate_draft(rule, req.test_cases, _raw_records(who))}


@app.get("/api/soc/rules")
async def soc_rules(who: rbac.Principal = Depends(require("soc.read"))):
    rules = soc_store.list_rules(who.tenant)
    for r in rules:
        r["hits"] = E(who).custom.hits.get(r["id"], 0)
    return {"rules": rules}


class RuleSave(BaseModel):
    rule: dict


@app.post("/api/soc/rules")
async def soc_rule_save(req: RuleSave, who: rbac.Principal = Depends(require("ai.use"))):
    """Save a rule as a draft (disabled). Enabling needs rules.manage."""
    rule = phase4.assemble({"local_rule": req.rule, **{k: v for k, v in req.rule.items() if k != "conditions"}})
    errs = phase4.validate_rule(rule)
    if errs:
        raise HTTPException(422, "; ".join(errs))
    existing = soc_store.list_rules(who.tenant)
    rule["id"] = req.rule.get("id") if req.rule.get("id") in {r["id"] for r in existing} \
        else f"CUS-{len(existing) + 1:03d}"
    rule.update(status="disabled", created_by=who.name, updated_at=time.time())
    soc_store.save_rule(rule, who.tenant)
    E(who).custom.load(soc_store.list_rules(who.tenant))
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.rule_save", target=rule["id"], purpose=rule.get("title", "")[:300],
                 legal_basis="own_asset", case_ref=None, result={"status": "disabled"})
    return rule


class RuleStatus(BaseModel):
    status: Literal["enabled", "disabled"]


@app.patch("/api/soc/rules/{rule_id}")
async def soc_rule_status(rule_id: str, req: RuleStatus, who: rbac.Principal = Depends(require("rules.manage"))):
    rule = next((r for r in soc_store.list_rules(who.tenant) if r["id"] == rule_id), None)
    if rule is None:
        raise HTTPException(404, "rule not found")
    rule.update(status=req.status, status_by=who.name, updated_at=time.time())
    soc_store.save_rule(rule, who.tenant)
    E(who).custom.load(soc_store.list_rules(who.tenant))
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=who.name, module="soc.rule_status", target=rule_id, purpose=req.status,
                 legal_basis="own_asset", case_ref=None, result={"status": req.status})
    return rule


@app.get("/api/soc/agents/risk")
async def soc_agent_risk(who: rbac.Principal = Depends(require("soc.read"))):
    e, now = E(who), time.time()
    out = []
    for ag in e.agents.agents.values():
        alerts = [a for a in e.events if a.get("agent") == ag["id"] and now - a["ts"] <= 86400]
        recs = [r for r in e.agents.records if r.get("agent") == ag["id"]][-300:]
        out.append(phase4.agent_risk(ag, alerts, recs))
    return {"agents": sorted(out, key=lambda x: -x["score"])}


@app.get("/api/soc/incidents/{inc_id}/response")
async def soc_response_plan(inc_id: int, who: rbac.Principal = Depends(require("soc.read"))):
    inc = _find_incident(inc_id, who)
    return phase4.response_plan(inc, inc.get("response"))


class StepUpdate(BaseModel):
    done: bool


@app.post("/api/soc/incidents/{inc_id}/response/{step_id}")
async def soc_response_step(inc_id: int, step_id: str, req: StepUpdate,
                            who: rbac.Principal = Depends(require("incident.write"))):
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


@app.patch("/api/soc/incidents/{inc_id}")
async def soc_update_incident(inc_id: int, req: IncidentUpdate, who: rbac.Principal = Depends(require("incident.write"))):
    """Analyst workflow: status, assignee and notes. Every change is written to the audit log."""
    if not (req.status or req.assignee is not None or req.note or req.verdict is not None):
        raise HTTPException(422, "nothing to update")
    name = actor(who, req.analyst)
    inc = E(who).update_incident(inc_id, name, req.status, req.assignee, req.note, verdict=req.verdict)
    if inc is None:
        raise HTTPException(404, "incident not found")
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=name, module="soc.incident", target=f"incident:{inc_id}",
                 purpose=req.note or f"status={req.status} assignee={req.assignee}", legal_basis="own_asset",
                 case_ref=f"INC-{inc_id}", result={k: v for k, v in req.model_dump().items() if v is not None})
    return inc


# ---------- analyst workspace: overview widgets, tasks, notifications ----------
@app.get("/api/soc/overview")
async def soc_overview(who: rbac.Principal = Depends(require("soc.read"))):
    """Homepage widgets: pending alerts, opened cases, alert list with occurrences + urgency, events by data source,
    top observed threats (24 h) and task counts. Computed from the tenant's live window plus persisted counters."""
    eng = E(who)
    now = time.time()
    events = list(eng.events)
    alerts = workspace.alert_summary(events, eng.incidents)
    tasks = soc_store.list_tasks(who.tenant)
    return {"pending_alerts": sum(1 for a in alerts if a["status"] in ("new", "open")),
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


@app.get("/api/soc/tasks")
async def soc_tasks(status: str | None = None, q: str | None = None, assignee: str | None = None,
                    who: rbac.Principal = Depends(require("soc.read"))):
    items = soc_store.list_tasks(who.tenant)
    if status:
        items = [t for t in items if t["status"] in status.split(",")]
    if assignee:
        items = [t for t in items if t.get("assignee") == assignee]
    if q:
        ql = q.lower()
        items = [t for t in items if ql in t["name"].lower() or ql in (t.get("description") or "").lower()]
    return {"tasks": items, "by_status": workspace.by_status(soc_store.list_tasks(who.tenant)),
            "statuses": [{"id": s, "th": workspace.TASK_TH[s]} for s in workspace.TASK_STATUSES]}


@app.post("/api/soc/tasks")
async def soc_task_create(req: TaskIn, who: rbac.Principal = Depends(require("incident.write"))):
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
async def soc_task_update(task_id: int, req: TaskPatch, who: rbac.Principal = Depends(require("incident.write"))):
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
async def soc_notify_rule_test(req: NotifyRule, who: rbac.Principal = Depends(require("soc.read"))):
    return {"matches": notify_rules.test_rule(req.model_dump(), list(E(who).incidents.values()))}


@app.post("/api/soc/notify-rules")
async def soc_notify_rule_create(req: NotifyRule, who: rbac.Principal = Depends(require("rules.manage"))):
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
async def soc_notify_rule_update(rule_id: int, req: NotifyRule, who: rbac.Principal = Depends(require("rules.manage"))):
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
async def soc_notify_rule_delete(rule_id: int, who: rbac.Principal = Depends(require("rules.manage"))):
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


@app.get("/api/soc/landscape")
async def soc_landscape(hours: int = 24, who: rbac.Principal = Depends(require("soc.read"))):
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
                     who: rbac.Principal = Depends(require("soc.read"))):
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
                     page: int = 1, size: int = 25, hours: int = 24, who: rbac.Principal = Depends(require("soc.read"))):
    now = time.time()
    events = _tenant_events(who, now - max(1, min(hours, 24 * 90)) * 3600, now)
    incs = dict(E(who).incidents)
    for e in events:  # older persisted incidents that are no longer in memory
        iid = e.get("incident_id")
        if iid and iid not in incs and e.get("simulated") is False:
            inc = soc_store.incident(iid, who.tenant)
            if inc:
                incs[iid] = inc
    return explorer.alerts_page(events, incs, status, severity, q[:200], real_only, sort, page, size)


def _find_incident(inc_id: int, who: rbac.Principal) -> dict:
    inc = E(who).incidents.get(inc_id) or soc_store.incident(inc_id, who.tenant)
    if inc is None:
        raise HTTPException(404, "incident not found")
    return inc


@app.get("/api/soc/incidents")
async def soc_incidents(status: str | None = None, real_only: bool = True, limit: int = 200,
                        who: rbac.Principal = Depends(require("soc.read"))):
    """Incident list. real_only (default) reads persisted cases from SQLite; otherwise the live in-memory set."""
    limit = min(max(limit, 1), 1000)
    if real_only:
        return soc_store.incidents(status, limit, who.tenant)
    items = sorted(E(who).incidents.values(), key=lambda i: -i["last_ts"])
    return [i for i in items if not status or i["status"] == status][:limit]


@app.get("/api/soc/incidents/{inc_id}")
async def soc_incident(inc_id: int, who: rbac.Principal = Depends(require("soc.read"))):
    return _find_incident(inc_id, who)


@app.get("/api/soc/incidents/{inc_id}/report", response_class=HTMLResponse)
async def soc_incident_report(inc_id: int, analyst: str = "", who: rbac.Principal = Depends(require("soc.read"))):
    html = soc_report.html_report(_find_incident(inc_id, who), who.name if who.named else analyst[:80])
    return HTMLResponse(html, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                                  "script-src 'unsafe-inline'"})


@app.get("/api/soc/incidents.csv")
async def soc_incidents_csv(status: str | None = None, real_only: bool = True, who: rbac.Principal = Depends(require("soc.read"))):
    items = await soc_incidents(status, real_only, 1000, who)
    return Response(soc_report.csv_export(items), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="soc-incidents.csv"'})


@app.post("/api/soc/agents/{agent_id}/contain")
async def soc_contain(agent_id: str, req: ContainRequest, who: rbac.Principal = Depends(require("respond"))):
    """Response action: revoke the agent's token / suspend it (simulated). Logged in the audit log."""
    if agent_id not in E(who).agents.agents:
        raise HTTPException(404, "unknown agent")
    result = E(who).agents.contain(agent_id, req.contain)
    if E(who).persist and not E(who).agents.agents[agent_id].get("demo"):
        soc_store.save_agents([E(who).agents.agents[agent_id]], who.tenant)
    audit.record(tenant=who.tenant, client_ip=who.ip, analyst=actor(who, req.analyst), module="soc.contain" if req.contain else "soc.release",
                 target=agent_id, purpose=req.reason, legal_basis="own_asset", case_ref=None,
                 result={"contained": req.contain, "simulated": True})
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


app.mount("/static", StaticFiles(directory=STATIC), name="static")
