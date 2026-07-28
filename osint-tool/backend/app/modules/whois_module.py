"""
WHOIS module: registrar, dates, status, nameservers, owner, location and
contact emails. Free, no API key required. Uses python-whois (wrapped in
a thread because the library is synchronous/blocking).

Values are deduplicated (case-insensitive) to avoid repeating nameservers
or emails that the record returns in different capitalizations — reduces
noise without inventing data.

TIMEOUT: python-whois opens a raw socket to the registry and has no timeout
of its own, so an unresponsive WHOIS server used to keep the whole scan
waiting forever. The lookup is now bounded by WHOIS_TIMEOUT. The worker
thread cannot be killed (that is a limitation of the blocking library), but
it no longer holds the request open — this is also why the structured `rdap`
module exists alongside this one.
"""

import asyncio
from datetime import date, datetime

import whois

from ..core.base import OSINTModule, register
from ..core.config import settings
from ..core.logging import get_logger
from ..core.models import Finding, TargetType

log = get_logger("whois")


def _fmt(v) -> str:
    """Normalize dates so that naive and tz-aware do NOT duplicate."""
    if isinstance(v, datetime):
        return v.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, date):
        return v.strftime("%Y-%m-%d")
    return str(v).strip()


@register
class WhoisModule(OSINTModule):
    name = "whois"
    supported_types = [TargetType.DOMAIN]

    @property
    def timeout(self) -> float:  # type: ignore[override]
        # Slightly above the inner timeout so the inner one reports first.
        return settings.whois_timeout + 5

    def _sync_lookup(self, domain: str) -> list[Finding]:
        data = whois.whois(domain)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        def add(label: str, value, category: str = "whois"):
            if not value:
                return
            vals = value if isinstance(value, list) else [value]
            for v in vals:
                if not v:
                    continue
                s = _fmt(v)
                key = (label, s.lower())
                if not s or key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(label=label, value=s, category=category))

        def add_date(label: str, value):
            # Dates often come as a list of the SAME date in multiple
            # representations: keep only the first.
            if isinstance(value, list):
                value = value[0] if value else None
            add(label, value)

        add("Registrar", data.registrar)
        add("Registrar URL", getattr(data, "registrar_url", None))
        add("WHOIS server", getattr(data, "whois_server", None))
        add_date("Creation date", data.creation_date)
        add_date("Updated date", getattr(data, "updated_date", None))
        add_date("Expiration date", data.expiration_date)

        # Domain age: derived from the creation date (older domains are more
        # established / less likely to be throwaway). Real, computed value.
        created = data.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if isinstance(created, datetime):
            try:
                age_days = (datetime.now() - created.replace(tzinfo=None)).days
                if age_days >= 0:
                    years = age_days // 365
                    rem = (age_days % 365) // 30
                    add("Domain age", f"{years}y {rem}m ({age_days} days)")
            except (TypeError, ValueError, OverflowError) as exc:
                # WHOIS text formats vary per TLD; a bad date must be visible
                # in the logs instead of vanishing into `except: pass`.
                log.debug("whois.age_parse_failed", domain=domain, error=str(exc))

        # Days until expiration: derived and reliable (or the domain lapsed).
        exp = data.expiration_date
        if isinstance(exp, list):
            exp = exp[0] if exp else None
        if isinstance(exp, datetime):
            try:
                days = (exp.replace(tzinfo=None) - datetime.now()).days
                if days >= 0:
                    add("Days until expiration", str(days))
                else:
                    add("Domain status", f"EXPIRED ({abs(days)} days ago)")
            except (TypeError, ValueError, OverflowError) as exc:
                log.debug("whois.expiry_parse_failed", domain=domain, error=str(exc))

        add("Status (EPP)", getattr(data, "status", None))
        add("DNSSEC", getattr(data, "dnssec", None))
        add("Nameserver", data.name_servers)
        add("Contact email", data.emails, category="whois_email")
        add("Registrant", getattr(data, "name", None))
        add("Organization", getattr(data, "org", None))
        add("Address", getattr(data, "address", None))
        add("City", getattr(data, "city", None))
        add("State/Province", getattr(data, "state", None))
        add("Country", getattr(data, "country", None))
        return findings

    async def _run(self, target: str) -> list[Finding]:
        # python-whois is blocking: run it in a thread, under a hard deadline.
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._sync_lookup, target),
                timeout=settings.whois_timeout,
            )
        except TimeoutError:
            log.warning("whois.timeout", domain=target, limit=settings.whois_timeout)
            return [
                Finding(
                    label="WHOIS",
                    value=f"No answer from the registry within {settings.whois_timeout}s",
                    category="whois",
                    confidence=0.9,
                )
            ]
