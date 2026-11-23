"""IP reconnaissance: reverse DNS, RDAP ownership, optional geolocation."""
import dns.reversename

from app.config import settings
from app import vt
from app.modules.common import dns_query, http_client, run_checks
from app.validators import ValidationError, is_public_ip


async def reverse_dns(ip: str) -> dict:
    ptr = await dns_query(dns.reversename.from_address(ip).to_text(), "PTR")
    return {"ptr": [p.rstrip(".") for p in ptr]}


async def rdap_ip(ip: str) -> dict:
    async with http_client(follow_redirects=True) as c:
        r = await c.get(f"https://rdap.org/ip/{ip}")
    r.raise_for_status()
    j = r.json()
    return {
        "network": j.get("name"),
        "handle": j.get("handle"),
        "range": f"{j.get('startAddress')} - {j.get('endAddress')}",
        "country": j.get("country"),
        "type": j.get("type"),
        "cidr": [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
                 for c in j.get("cidr0_cidrs", [])],
    }


async def geolocation(ip: str) -> dict:
    if not settings.ipinfo_token:
        return {"skipped": "Set IPINFO_TOKEN to enable geolocation/ASN lookup"}
    async with http_client() as c:
        r = await c.get(f"https://ipinfo.io/{ip}/json",
                        headers={"Authorization": f"Bearer {settings.ipinfo_token}"})
    r.raise_for_status()
    j = r.json()
    return {k: j.get(k) for k in ("city", "region", "country", "loc", "org", "timezone")}


async def scan(ip: str) -> dict:
    if not is_public_ip(ip):
        raise ValidationError("only public IP addresses are supported")
    return await run_checks({
        "reverse_dns": lambda: reverse_dns(ip),
        "rdap": lambda: rdap_ip(ip),
        "geolocation": lambda: geolocation(ip),
        "virustotal": lambda: vt.osint_check(ip),
    })
