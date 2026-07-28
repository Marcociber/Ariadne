"""
Main API.

Endpoints:
  GET  /health              -> healthcheck (never rate-limited or authenticated)
  GET  /modules             -> list available modules and supported types
  POST /scan                -> run a scan on a target
  GET  /scan/stream         -> same scan, streamed per module (Server-Sent Events)
  GET  /history             -> list recent scans (persistent, paginated)
  GET  /history/{scan_id}   -> retrieve a stored scan
  DELETE /history/{scan_id} -> forget a stored scan

Run locally:
  uvicorn app.main:app --reload

Hardening (all configurable, all off by default so local use is unchanged):
  CORS_ORIGINS   restricts which browser origins may call the API
  API_KEY        requires an `X-API-Key` header on every endpoint but /health
  RATE_LIMIT     caps requests per client; /scan has its own tighter limit
"""

# NOTE: no `from __future__ import annotations` here. The slowapi decorator
# wraps the endpoint in its own module, so postponed (string) annotations
# would be resolved against slowapi's namespace and FastAPI could not find
# the request models.
import json
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from sse_starlette.sse import EventSourceResponse

from . import modules  # noqa: F401  -> registers all plugins
from .core import cache, history, net
from .core.config import settings
from .core.context import ScanOptions
from .core.logging import get_logger
from .core.models import ScanResponse, TargetType
from .core.orchestrator import Orchestrator

log = get_logger("api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Own the shared HTTP client and the Redis pool for the app's lifetime."""
    log.info(
        "api.startup",
        cors_origins=settings.cors_origin_list,
        auth="api-key" if settings.api_key else "none",
        rate_limit=settings.rate_limit,
    )
    net.get_client()
    yield
    await net.close_client()
    await cache.close()


app = FastAPI(
    title="ARIADNE — OSINT All-in-One",
    description="OSINT dashboard that aggregates free sources with no API key.",
    version="0.2.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------- rate limit
# A single POST /scan of type `username` fans out to dozens of outbound
# requests, so an unlimited API is a traffic amplifier against third parties.
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# --------------------------------------------------------------------- CORS
# Previously `allow_origins=["*"]` with no authentication, which let any page
# the user visited drive their backend and read their scan history.
_allow_all = settings.cors_origin_list == ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=not _allow_all,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

orchestrator = Orchestrator()


# --------------------------------------------------------------------- auth
async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Enforce the static API key when one is configured.

    With API_KEY unset (the default) this is a no-op, so running locally needs
    no credentials.
    """
    if not settings.api_key:
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")


Protected = Depends(require_api_key)


# ------------------------------------------------------------------ schemas
class ScanRequest(BaseModel):
    """Validated scan request.

    `target` is length-bounded and `target_type` is a real enum, so bad input
    is rejected with a 422 instead of being silently ignored.
    """

    target: str = Field(min_length=1, max_length=settings.max_target_length)
    # User-selected type. None (or the string "auto") means autodetect.
    target_type: TargetType | None = None
    # Skip the cache and re-query every source.
    refresh: bool = False
    # Per-scan override for the username module's site count.
    max_sites: int | None = Field(default=None, ge=1, le=settings.maigret_max_sites)

    @field_validator("target_type", mode="before")
    @classmethod
    def _auto_means_autodetect(cls, value: object) -> object:
        if isinstance(value, str) and value.strip().lower() in ("", "auto"):
            return None
        return value

    @field_validator("target")
    @classmethod
    def _strip(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("target must not be blank")
        return cleaned


# ---------------------------------------------------------------- endpoints
@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe. Deliberately unauthenticated: Docker uses it."""
    return {"status": "ok"}


@app.get("/modules", dependencies=[Protected])
async def list_modules() -> list[dict]:
    return [
        {
            "name": inst.name,
            "supported_types": [t.value for t in inst.supported_types],
            "requires_key": inst.requires_key,
            "available": inst.is_available(),
        }
        for inst in orchestrator.modules
    ]


@app.post("/scan", response_model=ScanResponse, dependencies=[Protected])
@limiter.limit(settings.scan_rate_limit)
async def scan(request: Request, req: ScanRequest) -> ScanResponse:
    return await orchestrator.scan(
        req.target,
        req.target_type.value if req.target_type else None,
        refresh=req.refresh,
        options=ScanOptions(max_sites=req.max_sites),
    )


@app.get("/scan/stream", dependencies=[Protected])
@limiter.limit(settings.scan_rate_limit)
async def scan_stream(
    request: Request,
    target: str = Query(min_length=1, max_length=settings.max_target_length),
    target_type: str | None = Query(default=None),
    refresh: bool = Query(default=False),
    max_sites: int | None = Query(default=None, ge=1, le=settings.maigret_max_sites),
) -> EventSourceResponse:
    """Stream a scan as Server-Sent Events.

    A username scan takes tens of seconds; the results were already produced
    independently per module, so this only changes the transport. Events:
    `start`, one `module` per source as it finishes, then `done`.
    """

    async def publisher():
        try:
            async for event, payload in orchestrator.stream(
                target,
                target_type,
                refresh=refresh,
                options=ScanOptions(max_sites=max_sites),
            ):
                # The client may navigate away mid-scan; stop doing work.
                if await request.is_disconnected():
                    log.info("scan.stream_aborted", target=target)
                    break
                yield {"event": event, "data": json.dumps(payload)}
        except Exception as exc:
            log.warning("scan.stream_failed", target=target, error=str(exc))
            yield {"event": "error", "data": json.dumps({"detail": str(exc)})}

    return EventSourceResponse(publisher())


@app.get("/history", dependencies=[Protected])
async def history_list(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """Recent scans (newest first), without the full result payload."""
    return {
        "total": history.count(),
        "limit": limit,
        "offset": offset,
        "items": history.list_recent(limit, offset),
    }


@app.get("/history/{scan_id}", response_model=ScanResponse, dependencies=[Protected])
async def history_get(scan_id: int) -> dict:
    data = history.get(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return data


@app.delete("/history/{scan_id}", dependencies=[Protected])
async def history_delete(scan_id: int) -> dict[str, bool]:
    """Forget a stored scan. In an OSINT tool the history itself is sensitive."""
    if not history.delete(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}
