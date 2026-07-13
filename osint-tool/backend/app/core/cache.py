"""
Optional Redis cache for scan results.

Caching is entirely optional and fails safe: if Redis is not configured
(no REDIS_URL), the library is missing, or the connection fails, caching is
silently disabled and scans keep working — just without the cache.

Enable it by setting:
    REDIS_URL=redis://localhost:6379/0     (host/port of your Redis)
    CACHE_TTL=3600                          (seconds a result stays cached)
"""
import json
import os

_TTL = int(os.getenv("CACHE_TTL", "3600"))  # seconds
_client = None
_checked = False


def _get_client():
    """Lazily build a Redis client once. Returns None if unavailable."""
    global _client, _checked
    if _checked:
        return _client
    _checked = True
    url = os.getenv("REDIS_URL")
    if not url:
        return None
    try:
        import redis  # imported lazily so the dependency stays optional
        client = redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
        client.ping()
        _client = client
    except Exception:
        _client = None  # any failure -> caching disabled, never breaks a scan
    return _client


def enabled() -> bool:
    return _get_client() is not None


def get(key: str):
    client = _get_client()
    if not client:
        return None
    try:
        raw = client.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def set(key: str, value: dict) -> None:
    client = _get_client()
    if not client:
        return
    try:
        client.setex(key, _TTL, json.dumps(value))
    except Exception:
        pass
