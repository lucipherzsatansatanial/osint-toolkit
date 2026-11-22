"""OSINT Toolkit — FastAPI entry point."""
import asyncio
import hmac
import json
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import audit
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
    yield


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
@app.get("/api/soc/snapshot")
def soc_snapshot(_: str = Depends(guard)):
    return hub.engine.snapshot()


@app.get("/api/soc/cti")
async def soc_cti(refresh: bool = False, _: str = Depends(guard)):
    return await threatintel.get_all(force=refresh)


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
