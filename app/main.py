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

from app import audit
from app import ingest, soc_report, soc_store
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
    soc_store.init()
    soc_store.purge_expired()
    hub.engine.restore(soc_store.load())
    hub.engine.persist = True
    if settings.soc_autostart:
        hub.ensure_running()  # CTI feeds + correlation ticker run even before anyone opens the dashboard
    yield
    hub.stop()


app = FastAPI(title="OSINT Toolkit", version="0.1.0", lifespan=lifespan)

_hits: dict[str, deque] = defaultdict(deque)


def guard(request: Request, x_api_key: str = Header(default="")) -> str:
    if settings.api_key and not hmac.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(401, "invalid or missing X-API-Key")
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    q = _hits[client]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= settings.rate_limit_per_min:
        raise HTTPException(429, "rate limit exceeded")
    q.append(now)
    return client


class ScanRequest(BaseModel):
    module: Literal["domain", "ip", "email", "brand", "username"]
    target: str = Field(min_length=1, max_length=300)
    keyword: str | None = Field(default=None, max_length=40)
    analyst: str = Field(min_length=2, max_length=80)
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
async def scan(req: ScanRequest, client: str = Depends(guard)):
    if req.module in PERSONAL_DATA_MODULES and req.legal_basis not in LEGAL_BASES:
        raise HTTPException(422, "this module processes personal data: choose a PDPA legal basis")
    if req.legal_basis and req.legal_basis not in LEGAL_BASES:
        raise HTTPException(422, "unknown legal_basis")
    try:
        target, result = await run_scan(req)
    except ValidationError as e:
        raise HTTPException(422, str(e)) from e
    scan_id = audit.record(client_ip=client, analyst=req.analyst, module=req.module, target=target,
                           purpose=req.purpose, legal_basis=req.legal_basis, case_ref=req.case_ref,
                           result=result)
    return {"id": scan_id, "module": req.module, "target": target, "result": result}


@app.get("/api/history")
def history(limit: int = 50, _: str = Depends(guard)):
    return audit.history(min(max(limit, 1), 500))


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: int, _: str = Depends(guard)):
    row = audit.get(scan_id)
    if not row:
        raise HTTPException(404, "not found")
    return row


@app.get("/api/meta")
def meta():
    return {
        "auth_required": bool(settings.api_key),
        "legal_bases": LEGAL_BASES,
        "personal_data_modules": sorted(PERSONAL_DATA_MODULES),
        "integrations": {"hibp": bool(settings.hibp_api_key), "ipinfo": bool(settings.ipinfo_token)},
        "retention_days": audit.RETENTION_DAYS,
    }


# ---------- SOC dashboard: EDR / XDR / CTI ----------
# Engine state is mutated by the background tick on the event loop, so these handlers are
# async (run on the same loop) rather than sync (threadpool) to avoid concurrent mutation.
@app.get("/api/soc/snapshot")
async def soc_snapshot(_: str = Depends(guard)):
    return hub.engine.snapshot()


@app.get("/api/soc/cti")
async def soc_cti(refresh: bool = False, _: str = Depends(guard)):
    return threatintel.public(await threatintel.get_all(force=refresh))


@app.get("/api/soc/offensive-ai")
async def soc_offensive_ai(_: str = Depends(guard)):
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
async def soc_agents(_: str = Depends(guard)):
    m = hub.engine.agents
    return {"agents": m.inventory(), "rules": m.rules()}


@app.get("/api/soc/agents/sessions/{sid}")
async def soc_agent_session(sid: str, _: str = Depends(guard)):
    data = hub.engine.agents.session(sid[:20])
    if not data:
        raise HTTPException(404, "session not found")
    return data


@app.get("/api/soc/hunt")
async def soc_hunt(q: str = "", limit: int = 100, _: str = Depends(guard)):
    return {"query": q[:300], "results": hub.engine.agents.hunt(q[:300], min(max(limit, 1), 500))}


@app.post("/api/soc/ingest")
async def soc_ingest(request: Request, format: str = "auto", host: str | None = None,
                     client: str = Depends(guard)):
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
async def soc_register_agents(items: list[AgentSpec], _: str = Depends(guard)):
    """Upsert real AI agents and what they are allowed to do. Unregistered agents seen in logs raise AGT-011."""
    if len(items) > 500:
        raise HTTPException(413, "max 500 agents per request")
    out = hub.engine.agents.register([{**a.model_dump(), "account": a.account or a.id} for a in items])
    if hub.engine.persist:
        soc_store.save_agents([hub.engine.agents.agents[a["id"]] for a in out])
    return out


class ContainRequest(BaseModel):
    contain: bool = True
    analyst: str = Field(min_length=2, max_length=80)
    reason: str = Field(min_length=5, max_length=500)


class IncidentUpdate(BaseModel):
    analyst: str = Field(min_length=2, max_length=80)
    status: Literal["open", "investigating", "resolved", "false_positive", "closed"] | None = None
    assignee: str | None = Field(default=None, max_length=80)
    note: str | None = Field(default=None, max_length=4000)


@app.patch("/api/soc/incidents/{inc_id}")
async def soc_update_incident(inc_id: int, req: IncidentUpdate, client: str = Depends(guard)):
    """Analyst workflow: status, assignee and notes. Every change is written to the audit log."""
    if not (req.status or req.assignee is not None or req.note):
        raise HTTPException(422, "nothing to update")
    inc = hub.engine.update_incident(inc_id, req.analyst, req.status, req.assignee, req.note)
    if inc is None:
        raise HTTPException(404, "incident not found")
    audit.record(client_ip=client, analyst=req.analyst, module="soc.incident", target=f"incident:{inc_id}",
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
                        _: str = Depends(guard)):
    """Incident list. real_only (default) reads persisted cases from SQLite; otherwise the live in-memory set."""
    limit = min(max(limit, 1), 1000)
    if real_only:
        return soc_store.incidents(status, limit)
    items = sorted(hub.engine.incidents.values(), key=lambda i: -i["last_ts"])
    return [i for i in items if not status or i["status"] == status][:limit]


@app.get("/api/soc/incidents/{inc_id}")
async def soc_incident(inc_id: int, _: str = Depends(guard)):
    return _find_incident(inc_id)


@app.get("/api/soc/incidents/{inc_id}/report", response_class=HTMLResponse)
async def soc_incident_report(inc_id: int, analyst: str = "", _: str = Depends(guard)):
    html = soc_report.html_report(_find_incident(inc_id), analyst[:80])
    return HTMLResponse(html, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                                  "script-src 'unsafe-inline'"})


@app.get("/api/soc/incidents.csv")
async def soc_incidents_csv(status: str | None = None, real_only: bool = True, _: str = Depends(guard)):
    items = await soc_incidents(status, real_only, 1000, _)
    return Response(soc_report.csv_export(items), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="soc-incidents.csv"'})


@app.post("/api/soc/agents/{agent_id}/contain")
async def soc_contain(agent_id: str, req: ContainRequest, client: str = Depends(guard)):
    """Response action: revoke the agent's token / suspend it (simulated). Logged in the audit log."""
    if agent_id not in hub.engine.agents.agents:
        raise HTTPException(404, "unknown agent")
    result = hub.engine.agents.contain(agent_id, req.contain)
    if hub.engine.persist and not hub.engine.agents.agents[agent_id].get("demo"):
        soc_store.save_agents([hub.engine.agents.agents[agent_id]])
    audit.record(client_ip=client, analyst=req.analyst, module="soc.contain" if req.contain else "soc.release",
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
async def soc_stream(request: Request, _: str = Depends(guard)):
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
