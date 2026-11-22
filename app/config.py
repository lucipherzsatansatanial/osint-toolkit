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
    user_agent: str = os.getenv("OSINT_USER_AGENT", "OSINT-Toolkit/0.1 (+security research)")


settings = Settings()
