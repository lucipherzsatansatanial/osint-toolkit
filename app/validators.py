"""Input validation and SSRF protection.

Every target supplied by a user is validated here before any module touches it.
Outbound HTTP/TLS connections to user-supplied hosts must go through
`assert_public_host`, so the tool cannot be used to probe internal networks.
"""
import ipaddress
import re
import socket

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9.\-]{1,253})$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,40}$")
KEYWORD_RE = re.compile(r"^[a-z0-9\-]{3,40}$")


class ValidationError(ValueError):
    pass


def normalize_domain(value: str) -> str:
    v = value.strip().lower()
    v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0].rstrip(".")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValidationError(f"invalid domain: {value!r}") from e
    if not DOMAIN_RE.match(v):
        raise ValidationError(f"invalid domain: {value!r}")
    return v


def normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as e:
        raise ValidationError(f"invalid IP address: {value!r}") from e


def normalize_email(value: str) -> str:
    v = value.strip()
    m = EMAIL_RE.match(v)
    if not m:
        raise ValidationError(f"invalid email: {value!r}")
    local, domain = v.rsplit("@", 1)
    return f"{local}@{normalize_domain(domain)}"


def normalize_username(value: str) -> str:
    v = value.strip().lstrip("@")
    if not USERNAME_RE.match(v):
        raise ValidationError("username must be 2-40 chars: letters, digits, . _ -")
    return v


def normalize_keyword(value: str) -> str:
    v = value.strip().lower()
    if not KEYWORD_RE.match(v):
        raise ValidationError("keyword must be 3-40 chars: a-z, 0-9, -")
    return v


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_global and not addr.is_multicast


def assert_public_host(host: str) -> list[str]:
    """Resolve host and refuse if any address is non-public (SSRF guard).

    Returns the resolved addresses. Note: a DNS-rebinding attacker could still
    change the answer between this check and the connect; for a hardened
    deployment, also block private ranges at the network egress layer.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValidationError(f"cannot resolve {host}") from e
    addrs = sorted({i[4][0] for i in infos})
    bad = [a for a in addrs if not is_public_ip(a)]
    if bad:
        raise ValidationError(f"refusing non-public address for {host}: {', '.join(bad)}")
    return addrs
