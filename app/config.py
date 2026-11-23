"""Runtime configuration, read from environment variables."""
import os
from dataclasses import dataclass, field


def _list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    # If set, every /api call must send header X-API-Key with this value.
    api_key: str = os.getenv("OSINT_API_KEY", "")
    # Optional third-party keys (modules degrade gracefully when absent).
    hibp_api_key: str = os.getenv("HIBP_API_KEY", "")
    ipinfo_token: str = os.getenv("IPINFO_TOKEN", "")
    # VirusTotal API v3 (reputation look-ups). Defaults match the free public API quota.
    vt_api_key: str = os.getenv("VT_API_KEY", "")
    vt_rate_per_min: int = max(1, int(os.getenv("VT_RATE_PER_MIN", "4") or 4))
    vt_daily_quota: int = max(1, int(os.getenv("VT_DAILY_QUOTA", "500") or 500))
    vt_cache_ttl: int = max(60, int(os.getenv("VT_CACHE_TTL", "3600") or 3600))
    # extra internal domains never sent to VirusTotal (comma list, e.g. corp.example.co.th)
    vt_block_domains: list[str] = field(default_factory=lambda: [d.lower().strip(".") for d in _list("VT_BLOCK_DOMAINS")])
    # DNS resolvers; empty = system resolver.
    nameservers: list[str] = field(default_factory=lambda: _list("OSINT_NAMESERVERS"))
    http_timeout: float = float(os.getenv("OSINT_HTTP_TIMEOUT", "10"))
    db_path: str = os.getenv("OSINT_DB_PATH", "data/osint.db")
    rate_limit_per_min: int = int(os.getenv("OSINT_RATE_LIMIT", "30"))  # scans and other writes
    read_rate_limit_per_min: int = int(os.getenv("OSINT_READ_RATE_LIMIT", "300"))
    # one multiplier for demo-data volume and real-data capacity (in-memory windows, batch sizes, caps); 1 = original size
    soc_scale: int = max(1, min(20, int(os.getenv("SOC_SCALE", "5") or 5)))  # dashboard GETs (polling widgets)
    # SOC dashboard: "off" = real ingested telemetry only (no simulator).
    soc_simulation: bool = os.getenv("SOC_SIMULATION", "on").strip().lower() not in ("off", "0", "false", "no")
    # Start CTI refresh + ticker at app start (off in unit tests to avoid network access).
    soc_autostart: bool = os.getenv("SOC_AUTOSTART", "on").strip().lower() not in ("off", "0", "false", "no")
    # Offensive-AI rule OAI-002: hosts allowed to call AI model APIs, and the host-name prefixes treated as servers.
    ai_approved_hosts: list[str] = field(default_factory=lambda: _list("SOC_AI_APPROVED_HOSTS"))
    server_prefixes: list[str] = field(default_factory=lambda: _list("SOC_SERVER_PREFIXES") or ["SRV"])
    # Threat Map: the country attacks are drawn towards (ISO 3166-1 alpha-2)
    soc_home_country: str = (os.getenv("SOC_HOME_COUNTRY", "TH").strip().upper() or "TH")[:2]
    user_agent: str = os.getenv("OSINT_USER_AGENT", "OSINT-Toolkit/0.1 (+security research)")


settings = Settings()
