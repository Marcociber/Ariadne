"""
WHOIS module: registrar, dates, status, nameservers, owner, location and
contact emails. Free, no API key required. Uses python-whois (wrapped in
a thread because the library is synchronous/blocking).

Values are deduplicated (case-insensitive) to avoid repeating nameservers
or emails that the record returns in different capitalizations — reduces
noise without inventing data.
"""
import asyncio
from datetime import datetime, date

import whois

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType


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
        add("WHOIS server", getattr(data, "whois_server", None))
        add_date("Creation date", data.creation_date)
        add_date("Updated date", getattr(data, "updated_date", None))
        add_date("Expiration date", data.expiration_date)

        # Días hasta expiración: dato derivado y fiable (o el dominio ya caducó).
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
            except Exception:
                pass

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
        # python-whois is blocking: run it in a thread.
        return await asyncio.to_thread(self._sync_lookup, target)
