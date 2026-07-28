"""
Optional Redis cache for scan results.

Caching stays entirely optional and fails safe: with no REDIS_URL, no redis
library or an unreachable server, it is disabled and scans keep working.

Two problems from the first version are fixed here:

  * it used the SYNCHRONOUS redis client from inside async code, so every
    cache hit blocked the event loop. This uses `redis.asyncio`;
  * the availability check ran once per process, so a Redis that went down and
    came back stayed "unavailable" until the backend was restarted. The check
    is now retried every CACHE_RETRY_SECONDS.

Failures are logged instead of silently swallowed.
"""

from __future__ import annotations

import json
import time
from typing import Any

from .config import settings
from .logging import get_logger

log = get_logger("cache")

_client: Any = None
_last_check: float = 0.0
_disabled_until: float = 0.0


async def _get_client() -> Any:
    """Return a connected async Redis client, or None when unavailable."""
    global _client, _last_check, _disabled_until

    if not settings.redis_url:
        return None
    if _client is not None:
        return _client

    now = time.monotonic()
    if now < _disabled_until:
        return None
    _last_check = now

    try:
        from redis import asyncio as aioredis  # imported lazily: optional dependency

        client = aioredis.from_url(
            settings.redis_url,
            socket_connect_timeout=1,
            socket_timeout=1,
            decode_responses=True,
        )
        await client.ping()
    except Exception as exc:
        _disabled_until = now + settings.cache_retry_seconds
        log.warning("cache.unavailable", error=str(exc), retry_in=settings.cache_retry_seconds)
        return None

    _client = client
    log.info("cache.connected", url=settings.redis_url)
    return _client


async def enabled() -> bool:
    return await _get_client() is not None


async def get(key: str) -> dict | None:
    client = await _get_client()
    if not client:
        return None
    try:
        raw = await client.get(key)
        return json.loads(raw) if raw else None
    except Exception as exc:
        log.warning("cache.get_failed", key=key, error=str(exc))
        return None


async def set(key: str, value: dict) -> None:
    client = await _get_client()
    if not client:
        return
    try:
        await client.setex(key, settings.cache_ttl, json.dumps(value))
    except Exception as exc:
        log.warning("cache.set_failed", key=key, error=str(exc))


async def delete(key: str) -> None:
    """Drop one entry — used by the `refresh` flag to force a re-scan."""
    client = await _get_client()
    if not client:
        return
    try:
        await client.delete(key)
    except Exception as exc:
        log.warning("cache.delete_failed", key=key, error=str(exc))


async def close() -> None:
    """Release the connection pool (FastAPI lifespan shutdown)."""
    global _client
    if _client is not None:
        try:
            await _client.aclose()
        except Exception as exc:
            log.warning("cache.close_failed", error=str(exc))
        _client = None
