"""
Outbound network helpers: a shared HTTP client and an SSRF guard.

Two problems are solved here.

1. CONNECTION REUSE. Every module used to open its own `httpx.AsyncClient`
   (several of them one per call), so every request paid a fresh TLS
   handshake. `get_client()` hands out a single pooled client whose lifetime
   is tied to the FastAPI application.

2. SSRF. `POST /scan` accepts an arbitrary `target` AND lets the caller force
   the type, so `{"target": "169.254.169.254", "target_type": "domain"}`
   used to make the backend fetch the cloud metadata endpoint. Any module
   that fetches a user-supplied host must go through `safe_fetch()`, which
   resolves the name first, refuses non-global addresses, and re-validates
   every redirect hop instead of blindly following them.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

import httpx

from .config import settings
from .logging import get_logger

log = get_logger("net")

USER_AGENT = "Mozilla/5.0 (compatible; ariadne-osint/1.0)"

_client: httpx.AsyncClient | None = None


class UnsafeTargetError(Exception):
    """Raised when a target resolves to an address we refuse to contact."""


# --------------------------------------------------------------------------
# Shared client
# --------------------------------------------------------------------------
def get_client() -> httpx.AsyncClient:
    """Return the process-wide pooled HTTP client, creating it on demand."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=settings.http_timeout,
            headers={"User-Agent": USER_AGENT},
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=False,  # redirects are opt-in and validated per hop
        )
    return _client


async def close_client() -> None:
    """Close the shared client (called from the FastAPI lifespan shutdown)."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None


# --------------------------------------------------------------------------
# SSRF guard
# --------------------------------------------------------------------------
def _is_public_ip(raw: str) -> bool:
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    # `is_global` already excludes loopback, private, link-local, reserved,
    # multicast and unspecified ranges. The same check the IP module uses.
    return addr.is_global


async def resolve_public_ips(host: str) -> list[str]:
    """Resolve `host` and return its addresses, or raise UnsafeTargetError.

    A hostname is only accepted when EVERY address it resolves to is globally
    routable: a name that resolves to both a public and a private address
    (DNS rebinding) is rejected outright.
    """
    if settings.allow_private_targets:
        return []

    host = host.strip().strip(".").lower()
    if not host:
        raise UnsafeTargetError("empty host")

    # An IP literal needs no resolution.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not _is_public_ip(host):
            raise UnsafeTargetError(f"{host} is not a globally routable address")
        return [host]

    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        raise UnsafeTargetError(f"{host} points at the local machine")

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        raise UnsafeTargetError(f"cannot resolve {host}: {exc}") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise UnsafeTargetError(f"{host} did not resolve")
    for ip in ips:
        if not _is_public_ip(ip):
            raise UnsafeTargetError(f"{host} resolves to the non-public address {ip}")
    return ips


async def assert_safe_url(url: str) -> None:
    """Validate the scheme and host of a URL before it is requested."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError(f"refused scheme: {parsed.scheme or '(none)'}")
    if not parsed.hostname:
        raise UnsafeTargetError("URL has no host")
    await resolve_public_ips(parsed.hostname)


@dataclass
class FetchResult:
    """The parts of an HTTP response the modules actually use."""

    status_code: int
    url: str
    headers: dict[str, str]
    text: str
    redirects: list[str] = field(default_factory=list)
    truncated: bool = False


async def safe_fetch(
    url: str,
    *,
    max_redirects: int = 5,
    max_bytes: int = 200_000,
    timeout: float | None = None,
    headers: dict[str, str] | None = None,
) -> FetchResult:
    """GET a user-supplied URL with SSRF protection and a body size cap.

    Redirects are followed manually so that every hop is validated: a public
    host that 302s to `http://169.254.169.254/` is stopped at the redirect.
    """
    client = get_client()
    current = url
    redirects: list[str] = []

    for _ in range(max_redirects + 1):
        await assert_safe_url(current)
        request = client.build_request(
            "GET", current, headers=headers, timeout=timeout or settings.http_timeout
        )
        response = await client.send(request, stream=True, follow_redirects=False)
        try:
            location = response.headers.get("location")
            if response.is_redirect and location:
                nxt = urlparse(str(response.url.join(location)))
                # Drop any credentials smuggled into the redirect target.
                current = urlunparse(
                    (nxt.scheme, nxt.netloc.rsplit("@", 1)[-1], nxt.path, nxt.params, nxt.query, "")
                )
                redirects.append(current)
                continue

            body = bytearray()
            truncated = False
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) >= max_bytes:
                    truncated = True
                    break
            encoding = response.encoding or "utf-8"
            return FetchResult(
                status_code=response.status_code,
                url=str(response.url),
                headers={k.lower(): v for k, v in response.headers.items()},
                text=bytes(body[:max_bytes]).decode(encoding, errors="replace"),
                redirects=redirects,
                truncated=truncated,
            )
        finally:
            await response.aclose()

    raise UnsafeTargetError(f"too many redirects (>{max_redirects})")
