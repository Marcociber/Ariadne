"""
Email module (free, no API key required):
    - Public Gravatar profile (MD5 hash): avatar, name, location, bio,
        associated accounts and personal links.
    - Verifies whether the email domain has MX records (accepts email).
    - Detects known public email providers (exact match).
    - Checks domain anti-spoofing posture (SPF / DMARC).

Everything is based on verifiable responses (HTTP 200 from Gravatar =
profile exists; DNS records exist or not). No guesswork: no false positives.
"""
import hashlib

import dns.asyncresolver
import dns.resolver
import dns.exception
import httpx

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType

_DNS_ERRORS = (
    dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
    dns.resolver.NoNameservers, dns.exception.Timeout,
    dns.resolver.LifetimeTimeout,
)

# Proveedores de correo públicos (match EXACTO de dominio -> sin falsos positivos).
FREE_PROVIDERS = {
    "gmail.com": "Google Gmail", "googlemail.com": "Google Gmail",
    "outlook.com": "Microsoft Outlook", "hotmail.com": "Microsoft Hotmail",
    "live.com": "Microsoft Live", "msn.com": "Microsoft MSN",
    "yahoo.com": "Yahoo", "yahoo.es": "Yahoo", "ymail.com": "Yahoo",
    "proton.me": "Proton Mail", "protonmail.com": "Proton Mail",
    "icloud.com": "Apple iCloud", "me.com": "Apple iCloud",
    "gmx.com": "GMX", "gmx.es": "GMX", "zoho.com": "Zoho",
    "aol.com": "AOL", "mail.com": "Mail.com", "yandex.com": "Yandex",
    "tutanota.com": "Tuta", "tuta.com": "Tuta",
}


@register
class EmailModule(OSINTModule):
    name = "email"
    supported_types = [TargetType.EMAIL]

    def _resolver(self) -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver()
        r.lifetime = 5.0
        return r

    async def _check_gravatar(self, email: str) -> list[Finding]:
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/{h}.json"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers={"User-Agent": "osint-tool"})
        if resp.status_code != 200:
            return []

        findings = [
            Finding(label="Avatar (Gravatar)", value=f"https://www.gravatar.com/avatar/{h}", category="social"),
            Finding(label="Gravatar profile", value=f"https://gravatar.com/{h}", category="social"),
            Finding(label="MD5 hash", value=h, category="social", confidence=0.9),
        ]
        try:
            entry = resp.json()["entry"][0]
            if entry.get("displayName"):
                findings.append(Finding(label="Name (Gravatar)", value=entry["displayName"], category="social"))
            if entry.get("currentLocation"):
                findings.append(Finding(label="Location (Gravatar)", value=entry["currentLocation"], category="social"))
            about = (entry.get("aboutMe") or "").strip()
            if about:
                findings.append(Finding(label="Bio (Gravatar)", value=about[:200], category="social"))
            for acc in entry.get("accounts", []):
                if acc.get("url"):
                    findings.append(Finding(
                        label=f"Profile {acc.get('shortname', 'social')}",
                        value=acc["url"], category="social", confidence=0.9))
            for link in entry.get("urls", []):
                if link.get("value"):
                    findings.append(Finding(
                        label=f"Link{(' ' + link['title']) if link.get('title') else ''}",
                        value=link["value"], category="social", confidence=0.9))
        except Exception:
            pass
        return findings

    async def _check_mx(self, domain: str) -> list[Finding]:
        try:
            answers = await self._resolver().resolve(domain, "MX")
            hosts = sorted({str(r.exchange).rstrip(".") for r in answers})
        except _DNS_ERRORS:
            return []
        findings = [Finding(label="Receives email (MX)", value="Yes", category="email_infra")]
        findings += [Finding(label="MX server", value=h, category="email_infra") for h in hosts]
        return findings

    async def _check_security(self, domain: str) -> list[Finding]:
        """SPF y DMARC del dominio: postura antisuplantación (registros reales)."""
        findings: list[Finding] = []
        try:
            for rdata in await self._resolver().resolve(domain, "TXT"):
                val = str(rdata).strip('"')
                if val.lower().startswith("v=spf1"):
                    findings.append(Finding(label="SPF", value=val, category="email_security"))
        except _DNS_ERRORS:
            pass
        try:
            for rdata in await self._resolver().resolve(f"_dmarc.{domain}", "TXT"):
                val = str(rdata).strip('"')
                if val.lower().startswith("v=dmarc1"):
                    findings.append(Finding(label="DMARC", value=val, category="email_security"))
        except _DNS_ERRORS:
            pass
        return findings

    async def _run(self, target: str) -> list[Finding]:
        domain = target.split("@", 1)[1].lower()
        findings: list[Finding] = []

        provider = FREE_PROVIDERS.get(domain)
        if provider:
            findings.append(Finding(label="Email provider", value=provider, category="email_infra"))
        else:
            findings.append(Finding(label="Email domain", value=domain, category="email_infra"))

        findings += await self._check_gravatar(target)
        findings += await self._check_mx(domain)
        findings += await self._check_security(domain)
        return findings
