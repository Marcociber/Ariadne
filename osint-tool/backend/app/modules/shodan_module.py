"""
Shodan module (OPTIONAL — requires an API key).

Enriches a domain with exposure data from Shodan: resolved IP, organization,
open ports, detected services and known vulnerabilities (CVEs).

Enable it by setting SHODAN_API_KEY in the environment (.env). Without the key
the module is skipped automatically (requires_key = True + is_available()).
"""
import asyncio
import os
import socket

import httpx

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType


@register
class ShodanModule(OSINTModule):
    name = "shodan"
    supported_types = [TargetType.DOMAIN]
    requires_key = True

    def _key(self) -> str | None:
        return os.getenv("SHODAN_API_KEY")

    def is_available(self) -> bool:
        return bool(self._key())

    async def _run(self, target: str) -> list[Finding]:
        key = self._key()
        if not key:
            return []

        # Resolve the domain to an IP (Shodan indexes hosts by IP).
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, target)
        except Exception:
            return []

        findings = [Finding(label="Resolved IP", value=ip, category="shodan")]

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}", params={"key": key}
            )
        if resp.status_code != 200:
            return findings  # keep the resolved IP even if there is no host data

        data = resp.json()
        if data.get("org"):
            findings.append(Finding(label="Organization", value=str(data["org"]), category="shodan"))
        if data.get("os"):
            findings.append(Finding(label="OS", value=str(data["os"]), category="shodan"))
        ports = data.get("ports") or []
        if ports:
            findings.append(Finding(
                label="Open ports",
                value=", ".join(str(p) for p in sorted(ports)),
                category="shodan",
            ))
        for item in (data.get("data") or [])[:15]:
            port = item.get("port")
            product = (item.get("product") or item.get("_shodan", {}).get("module") or "").strip()
            transport = item.get("transport", "")
            value = product or f"{transport}/{port}".strip("/")
            findings.append(Finding(
                label=f"Service :{port}", value=value or str(port),
                category="shodan", confidence=0.9,
            ))
        for cve in list(data.get("vulns") or [])[:20]:
            findings.append(Finding(label="Vulnerability", value=str(cve), category="shodan", confidence=0.8))
        return findings
