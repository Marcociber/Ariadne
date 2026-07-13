"""
Email module (free, no API key required):
    - Address analysis: syntax validity, role-based detection, disposable /
      temporary provider detection, Gmail canonical form and plus-tagging.
    - Public Gravatar profile (MD5 + SHA-256 hash): avatar, name, location,
      bio, associated accounts and personal links.
    - Mail infrastructure: MX records, inferred mail provider, whether the
      domain hosts a website, and anti-spoofing posture (SPF / DMARC / MTA-STS).
    - OSINT pivots: the local part as a candidate username and ready-made
      web searches (only constructed, never queried).

Everything is based on verifiable responses (HTTP 200 from Gravatar =
profile exists; DNS records exist or not) or deterministic analysis of the
address itself. No guesswork: no false positives.
"""
import hashlib
import re
from urllib.parse import quote

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

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

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

# Local parts that identify a ROLE/shared mailbox rather than a person.
ROLE_ACCOUNTS = {
    "admin", "administrator", "info", "support", "sales", "contact", "help",
    "noreply", "no-reply", "donotreply", "postmaster", "hostmaster",
    "webmaster", "abuse", "billing", "marketing", "hello", "team", "office",
    "mail", "jobs", "hr", "careers", "security", "root", "service", "newsletter",
}

# Known disposable / throwaway email domains (exact match).
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "tempmail.com", "yopmail.com", "throwawaymail.com", "getnada.com",
    "trashmail.com", "sharklasers.com", "dispostable.com", "maildrop.cc",
    "fakeinbox.com", "mohmal.com", "mintemail.com", "spam4.me", "tempr.email",
    "emailondeck.com", "moakt.com", "luxusmail.org", "guerrillamail.info",
}

# Map MX hostname substrings to a recognizable mail provider.
MX_PROVIDERS = [
    ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"), ("protection.outlook.com", "Microsoft 365"),
    ("protonmail", "Proton Mail"), ("proton.me", "Proton Mail"),
    ("zoho", "Zoho Mail"), ("yahoodns", "Yahoo"), ("yahoo", "Yahoo"),
    ("icloud", "Apple iCloud"), ("apple.com", "Apple iCloud"),
    ("messagingengine.com", "Fastmail"), ("mailgun", "Mailgun"),
    ("sendgrid", "SendGrid"), ("pphosted.com", "Proofpoint"),
    ("mimecast", "Mimecast"), ("secureserver.net", "GoDaddy"),
    ("ovh.net", "OVH"), ("mail.ru", "Mail.ru"), ("yandex", "Yandex"),
    ("gmx.net", "GMX"), ("one.com", "One.com"), ("ionos", "IONOS"),
]


@register
class EmailModule(OSINTModule):
    name = "email"
    supported_types = [TargetType.EMAIL]

    def _resolver(self) -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver()
        r.lifetime = 5.0
        return r

    # ---------- address analysis (deterministic, offline) ----------
    def _analyze_address(self, email: str, local: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.append(Finding(
            label="Valid format",
            value="Yes" if _EMAIL_RE.match(email) else "No",
            category="email_address",
        ))

        base_local = local.split("+", 1)[0].lower()
        if local.lower() in ROLE_ACCOUNTS or base_local in ROLE_ACCOUNTS:
            findings.append(Finding(
                label="Account type", value="Role-based / shared mailbox",
                category="email_address", confidence=0.9))
        else:
            findings.append(Finding(
                label="Account type", value="Personal (likely)",
                category="email_address", confidence=0.6))

        if domain in DISPOSABLE_DOMAINS:
            findings.append(Finding(
                label="Disposable email", value="Yes (known throwaway provider)",
                category="email_address", confidence=0.9))

        # Plus-addressing / subaddressing (john+tag@ -> tag).
        if "+" in local:
            findings.append(Finding(
                label="Plus tag", value=local.split("+", 1)[1],
                category="email_address", confidence=0.9))

        # Gmail canonical form: dots are ignored and +tags stripped.
        if domain in ("gmail.com", "googlemail.com"):
            canonical = base_local.replace(".", "") + "@gmail.com"
            if canonical.lower() != email.lower():
                findings.append(Finding(
                    label="Canonical Gmail address", value=canonical,
                    category="email_address", confidence=0.9))
        return findings

    async def _check_gravatar(self, email: str) -> list[Finding]:
        norm = email.strip().lower().encode()
        md5 = hashlib.md5(norm).hexdigest()
        sha256 = hashlib.sha256(norm).hexdigest()
        url = f"https://www.gravatar.com/{md5}.json"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers={"User-Agent": "osint-tool"})
        if resp.status_code != 200:
            return []

        findings = [
            Finding(label="Avatar (Gravatar)", value=f"https://www.gravatar.com/avatar/{md5}", category="social"),
            Finding(label="Gravatar profile", value=f"https://gravatar.com/{md5}", category="social"),
            Finding(label="MD5 hash", value=md5, category="social", confidence=0.9),
            Finding(label="SHA-256 hash", value=sha256, category="social", confidence=0.9),
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
            return [Finding(label="Receives email (MX)", value="No MX records", category="email_infra", confidence=0.9)]
        findings = [Finding(label="Receives email (MX)", value="Yes", category="email_infra")]
        findings += [Finding(label="MX server", value=h, category="email_infra") for h in hosts]

        # Infer the mail provider from the MX hostnames.
        joined = " ".join(hosts).lower()
        for needle, provider in MX_PROVIDERS:
            if needle in joined:
                findings.append(Finding(label="Mail provider (MX)", value=provider, category="email_infra", confidence=0.85))
                break
        return findings

    async def _check_website(self, domain: str) -> list[Finding]:
        """Does the email domain also host a website (A record)?"""
        try:
            answers = await self._resolver().resolve(domain, "A")
            ips = sorted({str(r) for r in answers})
        except _DNS_ERRORS:
            return []
        return [Finding(label="Domain hosts website", value=f"Yes ({', '.join(ips[:3])})", category="email_infra")]

    async def _check_security(self, domain: str) -> list[Finding]:
        """SPF, DMARC y MTA-STS del dominio: postura antisuplantación (registros reales)."""
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
        try:
            for rdata in await self._resolver().resolve(f"_mta-sts.{domain}", "TXT"):
                val = str(rdata).strip('"')
                if val.lower().startswith("v=stsv1"):
                    findings.append(Finding(label="MTA-STS", value="Enabled (enforced TLS policy)", category="email_security", confidence=0.9))
        except _DNS_ERRORS:
            pass
        return findings

    def _pivots(self, email: str, local: str) -> list[Finding]:
        findings = [Finding(
            label="Possible username", value=local.split("+", 1)[0],
            category="pivot", confidence=0.5)]
        findings.append(Finding(label="Web search (exact)", value=f"https://www.google.com/search?q={quote(chr(34) + email + chr(34))}", category="pivot", confidence=0.5))
        findings.append(Finding(label="Search on GitHub", value=f"https://github.com/search?q={quote(email)}&type=code", category="pivot", confidence=0.5))
        return findings

    async def _run(self, target: str) -> list[Finding]:
        email = target.strip()
        local, _, domain = email.partition("@")
        domain = domain.lower()
        findings: list[Finding] = []

        provider = FREE_PROVIDERS.get(domain)
        if provider:
            findings.append(Finding(label="Email provider", value=provider, category="email_infra"))
        else:
            findings.append(Finding(label="Email domain", value=domain, category="email_infra"))

        findings += self._analyze_address(email, local, domain)
        findings += await self._check_gravatar(target)
        findings += await self._check_mx(domain)
        findings += await self._check_website(domain)
        findings += await self._check_security(domain)
        findings += self._pivots(email, local)
        return findings
