"""
crt.sh module: discovers subdomains via Certificate Transparency logs.
Free, no API key required.

crt.sh is an external service that sometimes returns 502/timeout. To avoid
losing data due to transient errors, we retry a couple of times with a
small backoff before giving up.
"""
import asyncio

import httpx

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType


@register
class CrtShModule(OSINTModule):
    name = "crtsh"
    supported_types = [TargetType.DOMAIN]

    async def _fetch(self, url: str) -> list | None:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; osint-tool/1.0)"}
        async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
            for attempt in range(3):
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        return resp.json()
                except (httpx.HTTPError, ValueError):
                    pass
                if attempt < 2:
                    await asyncio.sleep(1.5 * (attempt + 1))
        return None

    async def _run(self, target: str) -> list[Finding]:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        subdomains: set[str] = set()

        data = await self._fetch(url)
        if not data:
            return []

        issuers: set[str] = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                sub = sub.strip().lstrip("*.").lower()
                if sub.endswith(target) and sub != target:
                    subdomains.add(sub)
            issuer = (entry.get("issuer_name") or "").strip()
            if issuer:
                issuers.add(issuer)

        findings: list[Finding] = []
        if subdomains:
            findings.append(Finding(
                label="Subdomains found", value=str(len(subdomains)),
                category="subdomain"))
        findings += [
            Finding(label="Subdomain", value=s, category="subdomain")
            for s in sorted(subdomains)
        ]
        # Autoridades certificadoras que han emitido para el dominio (dato real
        # de los certificados; útil para perfilar la infraestructura).
        pretty_issuers: set[str] = set()
        for iss in issuers:
            # Extraer el O/CN legible del DN del emisor si está presente.
            label_parts = [p for p in iss.split(",") if p.strip().startswith(("O=", "CN="))]
            pretty = " · ".join(p.split("=", 1)[1] for p in label_parts) or iss
            pretty_issuers.add(pretty)
        for pretty in sorted(pretty_issuers):
            findings.append(Finding(label="Certificate issuer", value=pretty, category="cert"))

        return findings
