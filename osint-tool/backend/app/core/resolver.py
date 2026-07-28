"""
Shared DNS resolver with a DNS-over-HTTPS fallback.

Two improvements over the previous per-query resolver:

  * ONE resolver instance for the whole process. The DNS module built a new
    `dns.asyncresolver.Resolver()` for every lookup — roughly fifteen per
    domain scan — re-reading the system configuration each time.
  * A DoH FALLBACK. When the local resolver times out or returns SERVFAIL
    (captive portals, ISP resolvers that filter, Docker networks with a broken
    resolv.conf), the query is retried over Cloudflare and Google DNS-over-
    HTTPS. Answers are still authoritative data, so no false positives are
    introduced — only lost answers are recovered.
"""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
import httpx

from .config import settings
from .logging import get_logger
from .net import get_client

log = get_logger("resolver")

# Errors that mean "this name has no such record" (a definitive answer) or
# "the resolver could not answer" (worth retrying over DoH).
DEFINITIVE_ERRORS = (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN)
TRANSIENT_ERRORS = (
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
    dns.resolver.LifetimeTimeout,
)
DNS_ERRORS = DEFINITIVE_ERRORS + TRANSIENT_ERRORS

_DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)

_resolver: dns.asyncresolver.Resolver | None = None


def get_resolver() -> dns.asyncresolver.Resolver:
    """Return the shared resolver instance, building it once."""
    global _resolver
    if _resolver is None:
        r = dns.asyncresolver.Resolver()
        r.lifetime = 5.0
        r.timeout = 3.0
        _resolver = r
    return _resolver


async def _resolve_doh(name: str, rtype: str) -> list[str]:
    """Query the public DoH resolvers. Returns [] when none can answer."""
    client = get_client()
    for endpoint in _DOH_ENDPOINTS:
        try:
            resp = await client.get(
                endpoint,
                params={"name": name, "type": rtype},
                headers={"Accept": "application/dns-json"},
                timeout=settings.doh_timeout,
            )
            if resp.status_code != 200:
                continue
            answers = resp.json().get("Answer") or []
        except (httpx.HTTPError, ValueError) as exc:
            log.debug("resolver.doh_failed", endpoint=endpoint, error=str(exc))
            continue
        values = [a["data"] for a in answers if a.get("data")]
        if values:
            log.debug("resolver.doh_used", name=name, rtype=rtype, endpoint=endpoint)
            return values
    return []


async def resolve(name: str, rtype: str, *, allow_doh: bool = True) -> list[str]:
    """Resolve `name`/`rtype` and return the record values as strings.

    An empty list means "no such record" — callers treat that as a fact, not
    as an error, which is what keeps the tool free of false positives.
    """
    try:
        answers = await get_resolver().resolve(name, rtype)
    except DEFINITIVE_ERRORS:
        return []
    except TRANSIENT_ERRORS as exc:
        if not allow_doh:
            return []
        log.debug("resolver.local_failed", name=name, rtype=rtype, error=type(exc).__name__)
        # The endpoints are tried in order, so a hard cap on the whole fallback
        # is what keeps the cost bounded: this path is only reached after the
        # local resolver has ALREADY burned its own lifetime.
        budget = settings.doh_timeout * len(_DOH_ENDPOINTS)
        try:
            return await asyncio.wait_for(_resolve_doh(name, rtype), timeout=budget)
        except TimeoutError:
            log.debug("resolver.doh_budget_exceeded", name=name, rtype=rtype, budget=budget)
            return []
    except dns.exception.SyntaxError:
        return []
    return [str(rdata) for rdata in answers]


async def resolve_txt(name: str) -> list[str]:
    """TXT records with the surrounding quotes stripped."""
    return [v.strip('"') for v in await resolve(name, "TXT")]


async def reverse(ip: str) -> list[str]:
    """PTR records for an IP address, without the trailing dot."""
    try:
        rev = dns.reversename.from_address(ip)
    except (dns.exception.SyntaxError, ValueError):
        return []
    return [v.rstrip(".") for v in await resolve(str(rev), "PTR")]


async def resolve_many(name: str, rtypes: list[str]) -> dict[str, list[str]]:
    """Resolve several record types concurrently for the same name."""
    values = await asyncio.gather(*(resolve(name, rt) for rt in rtypes))
    return dict(zip(rtypes, values, strict=True))
