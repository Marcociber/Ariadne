"""
Centralized, typed configuration.

Every tunable of the application lives here instead of being read with
scattered `os.getenv` calls. Values are resolved, in order of precedence:

    1. Real environment variables (what Docker `environment:` injects).
    2. The `backend/.env` file, if present.
    3. The defaults declared below.

The `.env` file is located relative to THIS file, so it is found whether the
app is started from `backend/` (`uvicorn app.main:app`) or from anywhere else.
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# app/core/config.py -> app/core -> app -> backend
_BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------- optional API keys (key-based modules activate when set) ----------
    shodan_api_key: str | None = None
    hibp_api_key: str | None = None

    # ---------- cache ----------
    redis_url: str | None = None
    cache_ttl: int = 3600
    # How long to wait before retrying a Redis connection that previously
    # failed. Without this the cache stays dead until the process restarts.
    cache_retry_seconds: int = 60

    # ---------- history ----------
    history_db: str = "ariadne_history.db"
    # Retention: rows above this count (or older than this many days) are
    # pruned so the table cannot grow without bound.
    history_max_rows: int = 5000
    history_retention_days: int = 90

    # ---------- scan execution ----------
    # Hard ceiling for a whole scan and for any single module. Without these a
    # hung source keeps the HTTP request open indefinitely.
    scan_timeout: int = 120
    module_timeout: int = 60
    whois_timeout: int = 20
    http_timeout: float = 10.0
    max_target_length: int = 253
    # How many scans may run at the same time. One username scan alone fans
    # out to ~150 outbound requests, so unbounded concurrency turns the API
    # into a traffic amplifier against third parties.
    max_concurrent_scans: int = 4

    # ---------- username module (Maigret) ----------
    # Lowered from 150: this single number drives the perceived latency of the
    # whole application. Raise it for coverage, lower it for speed; the UI can
    # also override it per scan.
    maigret_top_sites: int = 75
    maigret_timeout: int = 10
    maigret_max_sites: int = 500  # ceiling for the per-scan override

    # ---------- API surface ----------
    # Comma-separated list of allowed browser origins. "*" keeps the previous
    # wide-open behaviour, which is fine for localhost but not for deployment.
    cors_origins: str = "*"
    # When set, every endpoint requires the `X-API-Key` header to match.
    # Unset (the default) keeps local usage friction-free.
    api_key: str | None = None
    rate_limit: str = "60/minute"
    scan_rate_limit: str = "10/minute"

    # ---------- outbound safety ----------
    # Modules that fetch a user-supplied host refuse private/reserved
    # addresses. Only enable this on a trusted, isolated network.
    allow_private_targets: bool = False
    # ip-api.com only offers HTTPS on paid plans; querying it leaks the target
    # IP in cleartext. Disable to drop that source from the consensus.
    enable_insecure_ipapi: bool = True

    # ---------- logging ----------
    log_level: str = "INFO"
    log_json: bool = False

    @property
    def cors_origin_list(self) -> list[str]:
        raw = (self.cors_origins or "").strip()
        if not raw or raw == "*":
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    """Process-wide singleton (cached so the .env is parsed only once)."""
    return Settings()


settings = get_settings()
