"""Shared helpers for OSINT modules."""
import asyncio
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.config import settings
from app.validators import ValidationError, assert_public_host


def http_client(**kw) -> httpx.AsyncClient:
    headers = {"User-Agent": settings.user_agent}
    headers.update(kw.pop("headers", {}))
    return httpx.AsyncClient(timeout=settings.http_timeout, headers=headers, **kw)


def resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    if settings.nameservers:
        r.nameservers = settings.nameservers
    r.lifetime = settings.http_timeout
    return r


async def dns_query(name: str, rtype: str) -> list[str]:
    try:
        ans = await resolver().resolve(name, rtype)
        return [r.to_text() for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return []


async def safe_get(url: str, max_redirects: int = 3) -> tuple[httpx.Response, list[str]]:
    """GET a user-influenced URL, re-checking the SSRF guard on every redirect hop."""
    chain: list[str] = []
    async with http_client(follow_redirects=False) as client:
        for _ in range(max_redirects + 1):
            host = urlsplit(url).hostname or ""
            await asyncio.to_thread(assert_public_host, host)
            resp = await client.get(url)
            chain.append(f"{resp.status_code} {url}")
            loc = resp.headers.get("location")
            if resp.is_redirect and loc:
                url = urljoin(url, loc)
                if urlsplit(url).scheme not in ("http", "https"):
                    raise ValidationError("redirect to unsupported scheme")
                continue
            return resp, chain
    raise ValidationError("too many redirects")


async def run_checks(checks: dict[str, Callable[[], Awaitable[Any]]]) -> dict[str, Any]:
    """Run named checks concurrently; one failing check never sinks the others."""
    async def wrap(fn):
        t0 = time.perf_counter()
        try:
            data = await fn()
            return {"ok": True, "data": data, "ms": round((time.perf_counter() - t0) * 1000)}
        except Exception as e:  # noqa: BLE001 - surface any module error to the UI
            return {"ok": False, "error": f"{type(e).__name__}: {e}",
                    "ms": round((time.perf_counter() - t0) * 1000)}

    names = list(checks)
    results = await asyncio.gather(*(wrap(checks[n]) for n in names))
    return dict(zip(names, results))
