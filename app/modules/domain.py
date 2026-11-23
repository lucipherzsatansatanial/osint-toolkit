"""Domain reconnaissance: DNS, RDAP (WHOIS), certificate transparency, HTTP & TLS."""
import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone

from app import vt
from app.modules.common import dns_query, http_client, run_checks, safe_get
from app.validators import assert_public_host

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS — enforce HTTPS",
    "content-security-policy": "CSP — mitigate XSS",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "Block MIME sniffing",
    "referrer-policy": "Control Referer leakage",
    "permissions-policy": "Restrict browser features",
}

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Drupal": [r"Drupal\.settings", r"/sites/default/files"],
    "Joomla": [r"/media/jui/", r"Joomla!"],
    "Next.js": [r"__NEXT_DATA__", r"/_next/static"],
    "Nuxt": [r"__NUXT__", r"/_nuxt/"],
    "React": [r"data-reactroot", r"react-dom"],
    "Vue.js": [r"data-v-[0-9a-f]{8}", r"vue(\.min)?\.js"],
    "Angular": [r"ng-version="],
    "Shopify": [r"cdn\.shopify\.com"],
    "Wix": [r"static\.wixstatic\.com"],
    "Google Analytics": [r"googletagmanager\.com/gtag", r"google-analytics\.com"],
    "Google Tag Manager": [r"googletagmanager\.com/gtm\.js"],
    "Facebook Pixel": [r"connect\.facebook\.net/.+/fbevents\.js"],
    "Cloudflare": [r"cdnjs\.cloudflare\.com", r"__cf_bm"],
    "jQuery": [r"jquery(\.min)?\.js"],
    "Bootstrap": [r"bootstrap(\.min)?\.(css|js)"],
}


async def dns_records(domain: str) -> dict:
    results = await asyncio.gather(*(dns_query(domain, t) for t in RECORD_TYPES))
    return {t: r for t, r in zip(RECORD_TYPES, results) if r}


def _rdap_events(events: list) -> dict:
    return {e.get("eventAction"): e.get("eventDate") for e in events or []}


def _rdap_entities(entities: list) -> list[dict]:
    out = []
    for ent in entities or []:
        name = None
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn":
                name = item[3]
        out.append({"roles": ent.get("roles", []), "name": name, "handle": ent.get("handle")})
    return out


async def rdap_domain(domain: str) -> dict:
    async with http_client(follow_redirects=True) as c:
        r = await c.get(f"https://rdap.org/domain/{domain}")
    if r.status_code == 404:
        # .th and some ccTLDs have no RDAP; say so instead of failing silently.
        return {"available": False, "note": "No RDAP service for this TLD (e.g. .th uses THNIC WHOIS: whois.thnic.co.th)"}
    r.raise_for_status()
    j = r.json()
    events = _rdap_events(j.get("events"))
    created = events.get("registration")
    age_days = None
    if created:
        try:
            age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
        except ValueError:
            pass
    return {
        "available": True,
        "handle": j.get("handle"),
        "status": j.get("status", []),
        "events": events,
        "age_days": age_days,
        "nameservers": [n.get("ldhName") for n in j.get("nameservers", [])],
        "entities": _rdap_entities(j.get("entities")),
    }


async def ct_subdomains(domain: str) -> dict:
    """Subdomains seen in public Certificate Transparency logs (crt.sh)."""
    async with http_client(follow_redirects=True) as c:
        r = await c.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                        timeout=30)
    r.raise_for_status()
    names: set[str] = set()
    for row in r.json():
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if n == domain or n.endswith("." + domain):
                names.add(n)
    subs = sorted(names)
    return {"count": len(subs), "subdomains": subs[:500], "truncated": len(subs) > 500}


def detect_tech(headers: dict, body: str) -> list[str]:
    found = set()
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server:
        found.add(f"Server: {server}")
    if powered:
        found.add(f"X-Powered-By: {powered}")
    if "cf-ray" in headers:
        found.add("Cloudflare")
    for tech, pats in TECH_SIGNATURES.items():
        if any(re.search(p, body, re.I) for p in pats):
            found.add(tech)
    return sorted(found)


def grade_headers(headers: dict) -> dict:
    present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = {h: d for h, d in SECURITY_HEADERS.items() if h not in headers}
    score = len(present)
    grade = "A" if score >= 6 else "B" if score >= 4 else "C" if score >= 2 else "F"
    return {"grade": grade, "score": f"{score}/{len(SECURITY_HEADERS)}",
            "present": present, "missing": missing}


async def http_probe(domain: str) -> dict:
    resp, chain = await safe_get(f"https://{domain}/")
    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text[:300_000]
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return {
        "final_url": str(resp.url),
        "status": resp.status_code,
        "redirect_chain": chain,
        "title": title.group(1).strip()[:200] if title else None,
        "headers": headers,
        "security_headers": grade_headers(headers),
        "technologies": detect_tech(headers, body),
    }


def _tls_cert_sync(domain: str) -> dict:
    addrs = assert_public_host(domain)
    ctx = ssl.create_default_context()
    with socket.create_connection((addrs[0], 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as s:
            cert = s.getpeercert()
            proto = s.version()
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    flat = lambda seq: {k: v for t in seq for k, v in t}  # noqa: E731
    return {
        "subject": flat(cert.get("subject", [])),
        "issuer": flat(cert.get("issuer", [])),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "days_left": (not_after - datetime.now(timezone.utc)).days,
        "san": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
        "protocol": proto,
    }


async def tls_cert(domain: str) -> dict:
    return await asyncio.to_thread(_tls_cert_sync, domain)


async def scan(domain: str) -> dict:
    return await run_checks({
        "dns": lambda: dns_records(domain),
        "whois_rdap": lambda: rdap_domain(domain),
        "subdomains_ct": lambda: ct_subdomains(domain),
        "http": lambda: http_probe(domain),
        "tls": lambda: tls_cert(domain),
        "virustotal": lambda: vt.osint_check(domain),
    })
