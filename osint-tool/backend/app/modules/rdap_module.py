"""
RDAP module (free, no API key required).

RDAP is the IETF's structured replacement for WHOIS: the registry answers
with JSON instead of free-form text whose layout changes from one TLD to the
next. That makes this module strictly more reliable than parsing WHOIS
output — no per-TLD regexes, no ambiguous dates.

It runs ALONGSIDE the `whois` module rather than replacing it: RDAP is
mandatory for gTLDs but several ccTLDs still only publish WHOIS, so dropping
WHOIS would lose data on exactly those domains.

Queries go through rdap.org, the IANA-bootstrap redirect service, so the
correct authoritative registry is reached without shipping a bootstrap table.
"""

import httpx

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType
from ..core.net import get_client

_RDAP_BASE = "https://rdap.org/domain/"

# RDAP event names -> human-readable label.
_EVENTS = {
    "registration": "Registered on",
    "expiration": "Expires on",
    "last changed": "Last changed",
    "transfer": "Last transfer",
    "last update of rdap database": "RDAP record updated",
}

# EPP status codes worth explaining rather than showing raw.
_STATUS_NOTES = {
    "client transfer prohibited": "Transfer lock (set by the registrar)",
    "server transfer prohibited": "Transfer lock (set by the registry)",
    "client delete prohibited": "Delete lock (set by the registrar)",
    "server delete prohibited": "Delete lock (set by the registry)",
    "client update prohibited": "Update lock (set by the registrar)",
    "client hold": "Domain not published in DNS (registrar hold)",
    "server hold": "Domain not published in DNS (registry hold)",
    "pending delete": "Pending deletion",
    "redemption period": "Expired — in redemption period",
}


def _vcard_field(entity: dict, field: str) -> str | None:
    """Pull one field out of the jCard array RDAP uses for contacts."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            return str(value).strip() or None
    return None


def _walk_entities(entities: list) -> list[dict]:
    """Flatten the (recursive) entity tree RDAP returns."""
    out: list[dict] = []
    for entity in entities or []:
        if not isinstance(entity, dict):
            continue
        out.append(entity)
        out.extend(_walk_entities(entity.get("entities") or []))
    return out


@register
class RDAPModule(OSINTModule):
    name = "rdap"
    supported_types = [TargetType.DOMAIN]

    async def _run(self, target: str) -> list[Finding]:
        try:
            resp = await get_client().get(
                f"{_RDAP_BASE}{target}",
                headers={"Accept": "application/rdap+json"},
                follow_redirects=True,
                timeout=15.0,
            )
        except httpx.HTTPError:
            return []

        if resp.status_code == 404:
            return [
                Finding(
                    label="RDAP",
                    value="Not registered (registry returned 404)",
                    category="rdap",
                    confidence=0.9,
                )
            ]
        if resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except ValueError:
            return []

        findings: list[Finding] = []
        if data.get("handle"):
            findings.append(Finding(label="Registry domain ID", value=str(data["handle"]), category="rdap"))
        if data.get("ldhName"):
            findings.append(
                Finding(label="Canonical name", value=str(data["ldhName"]).lower(), category="rdap")
            )

        # ---- events (dates) ----
        for event in data.get("events") or []:
            action = str(event.get("eventAction", "")).lower()
            date = str(event.get("eventDate", ""))[:10]
            label = _EVENTS.get(action)
            if label and date:
                findings.append(Finding(label=label, value=date, category="rdap"))

        # ---- status ----
        for status in data.get("status") or []:
            raw = str(status).strip()
            note = _STATUS_NOTES.get(raw.lower())
            findings.append(
                Finding(
                    label="Status (RDAP)",
                    value=f"{raw} — {note}" if note else raw,
                    category="rdap",
                )
            )

        # ---- nameservers ----
        for ns in data.get("nameservers") or []:
            name = (ns.get("ldhName") or "").strip().rstrip(".")
            if name:
                findings.append(Finding(label="Nameserver", value=name.lower(), category="rdap"))

        # ---- DNSSEC ----
        secure = data.get("secureDNS") or {}
        if isinstance(secure, dict) and "delegationSigned" in secure:
            findings.append(
                Finding(
                    label="DNSSEC (RDAP)",
                    value="Signed delegation" if secure["delegationSigned"] else "Unsigned",
                    category="rdap",
                    confidence=0.95,
                )
            )

        # ---- entities (registrar, abuse contact, registrant) ----
        for entity in _walk_entities(data.get("entities") or []):
            roles = [str(r).lower() for r in (entity.get("roles") or [])]
            name = _vcard_field(entity, "fn")
            email = _vcard_field(entity, "email")
            if "registrar" in roles:
                if name:
                    findings.append(Finding(label="Registrar", value=name, category="rdap"))
                for pid in entity.get("publicIds") or []:
                    if pid.get("identifier"):
                        findings.append(
                            Finding(
                                label="Registrar IANA ID",
                                value=str(pid["identifier"]),
                                category="rdap",
                                confidence=0.9,
                            )
                        )
            if "abuse" in roles and email:
                findings.append(Finding(label="Abuse contact", value=email, category="whois_email"))
            if "registrant" in roles:
                if name:
                    findings.append(Finding(label="Registrant", value=name, category="rdap"))
                if email:
                    findings.append(Finding(label="Registrant email", value=email, category="whois_email"))

        return findings
