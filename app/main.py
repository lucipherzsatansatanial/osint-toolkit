"""OSINT Toolkit — FastAPI entry point."""
import asyncio
import hmac
import json
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import audit, rbac
from app import ai, ingest, phase3, soc_report, soc_store
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


@asynccontextmanager
async def lifespan(_: FastAPI):
    audit.init()
    audit.purge_expired()
    rbac.init()
    soc_store.init()
    soc_store.purge_expired()
    hub.engine.restore(soc_store.load())
    hub.engine.persist = True
    notifier.reload()
    notifier.start()
    hub.engine.on_incident = notifier.offer
    if settings.soc_autostart:
        hub.ensure_running()  # CTI feeds + correlation ticker run even before anyone opens the dashboard
    yield
    hub.stop()
    notifier.stop()


app = FastAPI(title="OSINT Toolkit", version="0.1.0", lifespan=lifespan)

_hits: dict[str, deque] = defaultdict(deque)


def _authenticate(request: Request, x_api_key: str) -> rbac.Principal:
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    q = _hits[client]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= settings.rate_limit_per_min:
        raise HTTPException(429, "rate limit exceeded")
    q.append(now)
    if settings.api_key and x_api_key and hmac.compare_digest(x_api_key, settings.api_key):
        return rbac.Principal("admin (bootstrap key)", "admin", client, False, set(rbac.ROLES["admin"]))
    user = rbac.authenticate(x_api_key, client)
    if user:
        return user
    if not settings.api_key and not rbac.has_users():  # local development: no credentials configured at all
        return rbac.Principal("anonymous", "admin", client, False, set(rbac.ROLES["admin"]))
    raise HTTPException(401, "invalid or missing X-API-Key")


def require(perm: str):
    """Dependency: authenticated principal holding `perm` (see app.rbac.ROLES)."""
    def dep(request: Request, x_api_key: str = Header(default="")) -> rbac.Principal:
        who = _authenticate(request, x_api_key)
        if not who.can(perm):
            raise HTTPException(403, f"role '{who.role}' lacks permission '{perm}'")
        return who
    return dep


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
    scan_id = audit.record(client_ip=who.ip, analyst=actor(who, req.analyst), module=req.module, target=target,
                           purpose=req.purpose, legal_basis=req.legal_basis, case_ref=req.case_ref,
                           result=result)
    return {"id": scan_id, "module": req.module, "target": target, "result": result}


@app.get("/api/history")
def history(limit: int = 50, _: rbac.Principal = Depends(require("osint.history"))):
    return audit.history(min(max(limit, 1), 500))


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: int, _: rbac.Principal = Depends(require("osint.history"))):
    row = audit.get(scan_id)
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
            "named": who.named, "permissions": sorted(who.perms)}


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=63)
    role: Literal["viewer", "analyst", "lead", "admin", "ingest"]


class UserUpdate(BaseModel):
    role: Literal["viewer", "analyst", "lead", "admin", "ingest"] | None = None
    disabled: bool | None = None


@app.get("/api/users")
def users_list(_: rbac.Principal = Depends(require("users.manage"))):
    return {"users": rbac.list_users(), "roles": [{"id": r, "th": rbac.ROLE_TH[r], "permissions": sorted(p)}
                                                  for r, p in rbac.ROLES.items()]}


@app.post("/api/users")
def users_create(req: UserCreate, who: rbac.Principal = Depends(require("users.manage"))):
    try:
        token = rbac.create_user(req.username.strip().lower(), req.role, who.name)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    audit.record(client_ip=who.ip, analyst=who.name, module="rbac.create", target=req.username, purpose=f"role={req.role}",
                 legal_basis="own_asset", case_ref=None, result={"role": req.role})
    return {"username": req.username.strip().lower(), "role": req.role, "token": token,
            "note": "token แสดงครั้งเดียว — เก็บไว้ในที่ปลอดภัย"}


@app.post("/api/users/{username}/rotate")
def users_rotate(username: str, who: rbac.Principal = Depends(require("users.manage"))):
    token = rbac.rotate(username)
    if token is None:
        raise HTTPException(404, "user not found")
    audit.record(client_ip=who.ip, analyst=who.name, module="rbac.rotate", target=username, purpose="rotate token",
                 legal_basis="own_asset", case_ref=None, result={})
    return {"username": username, "token": token}


@app.patch("/api/users/{username}")
def users_update(username: str, req: UserUpdate, who: rbac.Principal = Depends(require("users.manage"))):
    if who.named and username == who.name and (req.disabled or (req.role and req.role != "admin")):
        raise HTTPException(409, "cannot disable or demote your own account")
    try:
        ok = rbac.update(username, req.role, req.disabled)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    if not ok:
        raise HTTPException(404, "user not found")
    audit.record(client_ip=who.ip, analyst=who.name, module="rbac.update", target=username, purpose=str(req.model_dump()),
                 legal_basis="own_asset", case_ref=None, result=req.model_dump())
    return {"username": username, **{k: v for k, v in req.model_dump().items() if v is not None}}


@app.get("/api/soc/snapshot")
async def soc_snapshot(_: rbac.Principal = Depends(require("soc.read"))):
    return hub.engine.snapshot()


@app.get("/api/soc/cti")
async def soc_cti(refresh: bool = False, _: rbac.Principal = Depends(require("soc.read"))):
    return threatintel.public(await threatintel.get_all(force=refresh))


@app.get("/api/soc/offensive-ai")
async def soc_offensive_ai(_: rbac.Principal = Depends(require("soc.read"))):
    """Offensive AI-agent framework coverage, rule hit counts and the hunting query library."""
    return {**hub.engine.offai.summary(), "queries": hunting_pack()}


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
async def soc_agents(_: rbac.Principal = Depends(require("soc.read"))):
    m = hub.engine.agents
    return {"agents": m.inventory(), "rules": m.rules()}


@app.get("/api/soc/agents/sessions/{sid}")
async def soc_agent_session(sid: str, _: rbac.Principal = Depends(require("soc.read"))):
    data = hub.engine.agents.session(sid[:20])
    if not data:
        raise HTTPException(404, "session not found")
    return data


@app.get("/api/soc/hunt")
async def soc_hunt(q: str = "", limit: int = 100, _: rbac.Principal = Depends(require("soc.read"))):
    return {"query": q[:300], "results": hub.engine.agents.hunt(q[:300], min(max(limit, 1), 500))}


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
    result = hub.engine.ingest_external(records)
    if not hub.subs:  # nobody watching: new viewers get these via the snapshot, so don't re-broadcast later
        hub.engine.drop_outbox()
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
    out = hub.engine.agents.register([{**a.model_dump(), "account": a.account or a.id} for a in items])
    if hub.engine.persist:
        soc_store.save_agents([hub.engine.agents.agents[a["id"]] for a in out])
    return out


class ContainRequest(BaseModel):
    contain: bool = True
    analyst: str | None = Field(default=None, max_length=80)  # ignored for named users
    reason: str = Field(min_length=5, max_length=500)


@app.get("/api/soc/notify")
async def soc_notify_status(_: rbac.Principal = Depends(require("soc.read"))):
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
    audit.record(client_ip=who.ip, analyst=name, module="soc.notify_test", target=",".join(notifier.channels()),
                 purpose="test alert channels", legal_basis="own_asset", case_ref=None,
                 result={n: ok for n, ok, _ in results})
    return {"results": {n: {"ok": ok, "detail": str(d)} for n, ok, d in results}}


# ---------- AI SOC Copilot ----------
@app.get("/api/soc/ai/status")
async def soc_ai_status(_: rbac.Principal = Depends(require("soc.read"))):
    return ai.status()


class AiSummaryRequest(BaseModel):
    refresh: bool = False


@app.post("/api/soc/incidents/{inc_id}/ai/summary")
async def soc_ai_summary(inc_id: int, req: AiSummaryRequest, who: rbac.Principal = Depends(require("ai.use"))):
    """AI alert summary + AI incident timeline + response actions. Cached on the incident until refresh=true."""
    inc = _find_incident(inc_id)
    if inc.get("ai") and not req.refresh:
        return inc["ai"]
    out = await ai.summarize(inc)
    out["generated_at"] = time.time()
    out["generated_by"] = who.name
    inc["ai"] = out
    hub.engine.incidents.setdefault(inc_id, inc)
    if inc.get("real"):
        hub.engine._dirty.add(inc_id)
        hub.engine.flush()
    audit.record(client_ip=who.ip, analyst=who.name, module="soc.ai_summary", target=f"incident:{inc_id}",
                 purpose="AI incident summary", legal_basis="own_asset", case_ref=f"INC-{inc_id}",
                 result={"source": out.get("source"), "model": out.get("model"), "redacted": out.get("redacted"),
                         "usage": out.get("usage")})
    return out


class AiAskRequest(BaseModel):
    question: str = Field(min_length=2, max_length=4000)
    history: list[dict] = Field(default_factory=list, max_length=20)


@app.post("/api/soc/incidents/{inc_id}/ai/ask")
async def soc_ai_ask(inc_id: int, req: AiAskRequest, who: rbac.Principal = Depends(require("ai.use"))):
    inc = _find_incident(inc_id)
    out = await ai.ask(inc, req.question, req.history)
    audit.record(client_ip=who.ip, analyst=who.name, module="soc.ai_ask", target=f"incident:{inc_id}",
                 purpose=req.question[:300], legal_basis="own_asset", case_ref=f"INC-{inc_id}",
                 result={"source": out.get("source"), "model": out.get("model"), "redacted": out.get("redacted"),
                         "usage": out.get("usage")})
    return out


# ---------- Phase 3: NL hunting, threat enrichment, attack chains ----------
def _hunt_data() -> dict:
    e = hub.engine
    return {"alerts": list(e.events), "agent_audit": list(e.agents.records), "incidents": list(e.incidents.values())}


class NlHuntRequest(BaseModel):
    question: str = Field(min_length=2, max_length=1000)


@app.post("/api/soc/hunt/nl")
async def soc_nl_hunt(req: NlHuntRequest, who: rbac.Principal = Depends(require("ai.use"))):
    out = await phase3.nl_hunt(req.question, _hunt_data(), time.time())
    audit.record(client_ip=who.ip, analyst=who.name, module="soc.ai_hunt", target="hunt", purpose=req.question[:300],
                 legal_basis="own_asset", case_ref=None,
                 result={"mode": out.get("mode"), "total": out.get("total"), "model": out.get("model"), "usage": out.get("usage")})
    return out


class EnrichRequest(BaseModel):
    indicator: str = Field(min_length=3, max_length=500)


@app.post("/api/soc/enrich")
async def soc_enrich(req: EnrichRequest, who: rbac.Principal = Depends(require("ai.use"))):
    out = await phase3.enrich(req.indicator, _hunt_data())
    audit.record(client_ip=who.ip, analyst=who.name, module="soc.ai_enrich", target=req.indicator[:200],
                 purpose="threat enrichment", legal_basis="own_asset", case_ref=None,
                 result={"matches": len(out["matches"]), "local_verdict": out["local_verdict"],
                         "ai": bool(out.get("ai")), "usage": (out.get("ai") or {}).get("usage")})
    return out


@app.get("/api/soc/chains")
async def soc_chains(_: rbac.Principal = Depends(require("soc.read"))):
    return {"chains": phase3.build_chains(list(hub.engine.incidents.values()))[:30]}


@app.post("/api/soc/chains/{chain_id}/ai")
async def soc_chain_ai(chain_id: str, who: rbac.Principal = Depends(require("ai.use"))):
    chain = next((c for c in phase3.build_chains(list(hub.engine.incidents.values())) if c["id"] == chain_id), None)
    if chain is None:
        raise HTTPException(404, "chain not found (chains are rebuilt from current incidents)")
    out = await ai.summarize(phase3.chain_as_incident(chain, hub.engine.incidents))
    audit.record(client_ip=who.ip, analyst=who.name, module="soc.ai_chain", target=chain_id, purpose="attack chain narrative",
                 legal_basis="own_asset", case_ref=chain_id,
                 result={"source": out.get("source"), "model": out.get("model"), "usage": out.get("usage")})
    return out


class IncidentUpdate(BaseModel):
    analyst: str | None = Field(default=None, max_length=80)  # ignored for named users
    status: Literal["open", "investigating", "resolved", "false_positive", "closed"] | None = None
    assignee: str | None = Field(default=None, max_length=80)
    note: str | None = Field(default=None, max_length=4000)


@app.patch("/api/soc/incidents/{inc_id}")
async def soc_update_incident(inc_id: int, req: IncidentUpdate, who: rbac.Principal = Depends(require("incident.write"))):
    """Analyst workflow: status, assignee and notes. Every change is written to the audit log."""
    if not (req.status or req.assignee is not None or req.note):
        raise HTTPException(422, "nothing to update")
    name = actor(who, req.analyst)
    inc = hub.engine.update_incident(inc_id, name, req.status, req.assignee, req.note)
    if inc is None:
        raise HTTPException(404, "incident not found")
    audit.record(client_ip=who.ip, analyst=name, module="soc.incident", target=f"incident:{inc_id}",
                 purpose=req.note or f"status={req.status} assignee={req.assignee}", legal_basis="own_asset",
                 case_ref=f"INC-{inc_id}", result={k: v for k, v in req.model_dump().items() if v is not None})
    return inc


def _find_incident(inc_id: int) -> dict:
    inc = hub.engine.incidents.get(inc_id) or soc_store.incident(inc_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    return inc


@app.get("/api/soc/incidents")
async def soc_incidents(status: str | None = None, real_only: bool = True, limit: int = 200,
                        _: rbac.Principal = Depends(require("soc.read"))):
    """Incident list. real_only (default) reads persisted cases from SQLite; otherwise the live in-memory set."""
    limit = min(max(limit, 1), 1000)
    if real_only:
        return soc_store.incidents(status, limit)
    items = sorted(hub.engine.incidents.values(), key=lambda i: -i["last_ts"])
    return [i for i in items if not status or i["status"] == status][:limit]


@app.get("/api/soc/incidents/{inc_id}")
async def soc_incident(inc_id: int, _: rbac.Principal = Depends(require("soc.read"))):
    return _find_incident(inc_id)


@app.get("/api/soc/incidents/{inc_id}/report", response_class=HTMLResponse)
async def soc_incident_report(inc_id: int, analyst: str = "", _: rbac.Principal = Depends(require("soc.read"))):
    html = soc_report.html_report(_find_incident(inc_id), _.name if _.named else analyst[:80])
    return HTMLResponse(html, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                                  "script-src 'unsafe-inline'"})


@app.get("/api/soc/incidents.csv")
async def soc_incidents_csv(status: str | None = None, real_only: bool = True, _: rbac.Principal = Depends(require("soc.read"))):
    items = await soc_incidents(status, real_only, 1000, _)
    return Response(soc_report.csv_export(items), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="soc-incidents.csv"'})


@app.post("/api/soc/agents/{agent_id}/contain")
async def soc_contain(agent_id: str, req: ContainRequest, who: rbac.Principal = Depends(require("respond"))):
    """Response action: revoke the agent's token / suspend it (simulated). Logged in the audit log."""
    if agent_id not in hub.engine.agents.agents:
        raise HTTPException(404, "unknown agent")
    result = hub.engine.agents.contain(agent_id, req.contain)
    if hub.engine.persist and not hub.engine.agents.agents[agent_id].get("demo"):
        soc_store.save_agents([hub.engine.agents.agents[agent_id]])
    audit.record(client_ip=who.ip, analyst=actor(who, req.analyst), module="soc.contain" if req.contain else "soc.release",
                 target=agent_id, purpose=req.reason, legal_basis="own_asset", case_ref=None,
                 result={"contained": req.contain, "simulated": True})
    return result


def sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


async def soc_events(request: Request, q: asyncio.Queue):
    try:
        yield sse("snapshot", hub.engine.snapshot())
        while not await request.is_disconnected():
            try:
                msg = await asyncio.wait_for(q.get(), timeout=15)
                yield sse("tick", msg)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
    finally:
        hub.unsubscribe(q)


@app.get("/api/soc/stream")
async def soc_stream(request: Request, _: rbac.Principal = Depends(require("soc.read"))):
    """Server-Sent Events. Read with fetch() so the X-API-Key header can be sent."""
    return StreamingResponse(soc_events(request, hub.subscribe()), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/soc")
def soc_page():
    return FileResponse(STATIC / "soc.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
