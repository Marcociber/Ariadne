"""
crt.sh module: discovers subdomains via Certificate Transparency logs.
Free, no API key required.

crt.sh is an external service that sometimes returns 502/timeout, so the
request is retried with exponential backoff (tenacity) instead of a hand-
rolled loop.

Subdomain membership is checked on LABEL BOUNDARIES via the Public Suffix
List. The previous `sub.endswith(target)` test accepted `noesejemplo.com`
as a subdomain of `ejemplo.com` — a real false positive, in a tool whose
stated value proposition is that it has none.
"""

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..core.base import OSINTModule, register
from ..core.domains import clean_host, is_subdomain_of
from ..core.models import Finding, TargetType
from ..core.net import get_client


class _TransientError(Exception):
    """crt.sh answered, but not with usable data."""


@register
class CrtShModule(OSINTModule):
    name = "crtsh"
    supported_types = [TargetType.DOMAIN]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1.5, min=1.5, max=6),
        retry=retry_if_exception_type((_TransientError, httpx.HTTPError)),
        reraise=True,  # surface the real cause, not tenacity's RetryError
    )
    async def _fetch(self, url: str) -> list:
        resp = await get_client().get(url, timeout=20.0)
        if resp.status_code != 200:
            raise _TransientError(f"crt.sh returned {resp.status_code}")
        try:
            return resp.json()
        except ValueError as exc:
            raise _TransientError("crt.sh returned a non-JSON body") from exc

    async def _run(self, target: str) -> list[Finding]:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        try:
            data = await self._fetch(url)
        except (_TransientError, httpx.HTTPError):
            return []
        if not data:
            return []

        subdomains: set[str] = set()
        issuers: set[str] = set()
        has_wildcard = False
        for entry in data:
            name_value = entry.get("name_value", "")
            for raw_name in name_value.split("\n"):
                raw = clean_host(raw_name)
                if raw.startswith("*."):
                    has_wildcard = True
                    raw = raw[2:]
                # Label-boundary check: `noesejemplo.com` is NOT under
                # `ejemplo.com`, however similar the strings look.
                if is_subdomain_of(raw, target):
                    subdomains.add(raw)
            issuer = (entry.get("issuer_name") or "").strip()
            if issuer:
                issuers.add(issuer)

        findings: list[Finding] = []
        if subdomains:
            findings.append(
                Finding(label="Subdomains found", value=str(len(subdomains)), category="subdomain")
            )
        findings.append(Finding(label="Certificates (CT log entries)", value=str(len(data)), category="cert"))
        if has_wildcard:
            findings.append(
                Finding(
                    label="Wildcard certificate",
                    value=f"Yes (*.{target} issued)",
                    category="cert",
                    confidence=0.9,
                )
            )
        findings += [Finding(label="Subdomain", value=s, category="subdomain") for s in sorted(subdomains)]

        # Certificate authorities that issued for the domain (real data from
        # the certificates; useful for profiling the infrastructure).
        pretty_issuers: set[str] = set()
        for iss in issuers:
            # Extract the readable O/CN from the issuer DN when present.
            label_parts = [p for p in iss.split(",") if p.strip().startswith(("O=", "CN="))]
            pretty = " · ".join(p.split("=", 1)[1] for p in label_parts) or iss
            pretty_issuers.add(pretty)
        findings += [
            Finding(label="Certificate issuer", value=p, category="cert") for p in sorted(pretty_issuers)
        ]
        return findings
