"""
Shodan module (OPTIONAL — requires an API key).

Enriches a domain with exposure data from Shodan: resolved IP, organization,
open ports, detected services and known vulnerabilities (CVEs).

Enable it by setting SHODAN_API_KEY in the environment (or backend/.env).
Without the key the module is skipped automatically
(requires_key = True + is_available()).

NOTE ON THE KEY: Shodan's API takes the key as a query parameter — that is
its design, not a choice made here — so the key appears in the URL and can be
recorded by intermediate proxies. Nothing in this codebase logs the URL.
"""

from ..core.base import OSINTModule, register
from ..core.config import settings
from ..core.logging import get_logger
from ..core.models import Finding, TargetType
from ..core.net import UnsafeTargetError, get_client, resolve_public_ips

log = get_logger("shodan")


@register
class ShodanModule(OSINTModule):
    name = "shodan"
    supported_types = [TargetType.DOMAIN]
    requires_key = True

    def _key(self) -> str | None:
        return settings.shodan_api_key

    def is_available(self) -> bool:
        return bool(self._key())

    async def _run(self, target: str) -> list[Finding]:
        key = self._key()
        if not key:
            return []

        # Resolve the domain to an IP (Shodan indexes hosts by IP). The same
        # guard the HTTP module uses: never look up an internal address.
        try:
            ips = await resolve_public_ips(target)
        except UnsafeTargetError as exc:
            log.info("shodan.refused", target=target, reason=str(exc))
            return [
                Finding(
                    label="Shodan lookup",
                    value=f"Refused: {exc}",
                    category="shodan",
                    confidence=0.9,
                )
            ]
        if not ips:
            return []
        ip = ips[0]

        findings = [Finding(label="Resolved IP", value=ip, category="shodan")]

        resp = await get_client().get(
            f"https://api.shodan.io/shodan/host/{ip}", params={"key": key}, timeout=15.0
        )
        if resp.status_code == 401:
            findings.append(
                Finding(
                    label="Shodan lookup",
                    value="API key rejected (check SHODAN_API_KEY)",
                    category="shodan",
                    confidence=0.9,
                )
            )
            return findings
        if resp.status_code == 429:
            findings.append(
                Finding(
                    label="Shodan lookup",
                    value="Rate limited by Shodan (result unknown)",
                    category="shodan",
                    confidence=0.9,
                )
            )
            return findings
        if resp.status_code != 200:
            # 404 simply means Shodan has never scanned this host.
            return findings

        data = resp.json()
        if data.get("org"):
            findings.append(Finding(label="Organization", value=str(data["org"]), category="shodan"))
        if data.get("os"):
            findings.append(Finding(label="OS", value=str(data["os"]), category="shodan"))
        ports = data.get("ports") or []
        if ports:
            findings.append(
                Finding(
                    label="Open ports",
                    value=", ".join(str(p) for p in sorted(ports)),
                    category="shodan",
                )
            )
        for item in (data.get("data") or [])[:15]:
            port = item.get("port")
            product = (item.get("product") or item.get("_shodan", {}).get("module") or "").strip()
            transport = item.get("transport", "")
            value = product or f"{transport}/{port}".strip("/")
            findings.append(
                Finding(
                    label=f"Service :{port}",
                    value=value or str(port),
                    category="shodan",
                    confidence=0.9,
                )
            )
        for cve in list(data.get("vulns") or [])[:20]:
            findings.append(Finding(label="Vulnerability", value=str(cve), category="shodan", confidence=0.8))
        return findings
