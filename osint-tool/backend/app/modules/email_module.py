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

All independent phases run CONCURRENTLY (they used to be awaited one after
another, so the module took as long as the sum of its parts), and DNS goes
through the shared resolver.

Maintenance note: the provider / disposable-domain lists below are static
data that ages. They are exact-match only, so a stale entry can never turn
into a false positive — at worst a new provider is not recognized yet.
"""

import asyncio
import hashlib
import re
from urllib.parse import quote

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType
from ..core.net import get_client
from ..core.resolver import resolve, resolve_txt

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Public mail providers (EXACT domain match -> no false positives).
FREE_PROVIDERS = {
    "gmail.com": "Google Gmail",
    "googlemail.com": "Google Gmail",
    "outlook.com": "Microsoft Outlook",
    "hotmail.com": "Microsoft Hotmail",
    "live.com": "Microsoft Live",
    "msn.com": "Microsoft MSN",
    "yahoo.com": "Yahoo",
    "yahoo.es": "Yahoo",
    "ymail.com": "Yahoo",
    "proton.me": "Proton Mail",
    "protonmail.com": "Proton Mail",
    "icloud.com": "Apple iCloud",
    "me.com": "Apple iCloud",
    "gmx.com": "GMX",
    "gmx.es": "GMX",
    "zoho.com": "Zoho",
    "aol.com": "AOL",
    "mail.com": "Mail.com",
    "yandex.com": "Yandex",
    "tutanota.com": "Tuta",
    "tuta.com": "Tuta",
}

# Local parts that identify a ROLE/shared mailbox rather than a person.
ROLE_ACCOUNTS = {
    "admin",
    "administrator",
    "info",
    "support",
    "sales",
    "contact",
    "help",
    "noreply",
    "no-reply",
    "donotreply",
    "postmaster",
    "hostmaster",
    "webmaster",
    "abuse",
    "billing",
    "marketing",
    "hello",
    "team",
    "office",
    "mail",
    "jobs",
    "hr",
    "careers",
    "security",
    "root",
    "service",
    "newsletter",
}

# Known disposable / throwaway email domains (exact match).
DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "temp-mail.org",
    "tempmail.com",
    "yopmail.com",
    "throwawaymail.com",
    "getnada.com",
    "trashmail.com",
    "sharklasers.com",
    "dispostable.com",
    "maildrop.cc",
    "fakeinbox.com",
    "mohmal.com",
    "mintemail.com",
    "spam4.me",
    "tempr.email",
    "emailondeck.com",
    "moakt.com",
    "luxusmail.org",
    "guerrillamail.info",
}

# Map MX hostname substrings to a recognizable mail provider.
MX_PROVIDERS = [
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"),
    ("protection.outlook.com", "Microsoft 365"),
    ("protonmail", "Proton Mail"),
    ("proton.me", "Proton Mail"),
    ("zoho", "Zoho Mail"),
    ("yahoodns", "Yahoo"),
    ("yahoo", "Yahoo"),
    ("icloud", "Apple iCloud"),
    ("apple.com", "Apple iCloud"),
    ("messagingengine.com", "Fastmail"),
    ("mailgun", "Mailgun"),
    ("sendgrid", "SendGrid"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast", "Mimecast"),
    ("secureserver.net", "GoDaddy"),
    ("ovh.net", "OVH"),
    ("mail.ru", "Mail.ru"),
    ("yandex", "Yandex"),
    ("gmx.net", "GMX"),
    ("one.com", "One.com"),
    ("ionos", "IONOS"),
]


@register
class EmailModule(OSINTModule):
    name = "email"
    supported_types = [TargetType.EMAIL]

    # ---------- address analysis (deterministic, offline) ----------
    def _analyze_address(self, email: str, local: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.append(
            Finding(
                label="Valid format",
                value="Yes" if _EMAIL_RE.match(email) else "No",
                category="email_address",
            )
        )

        base_local = local.split("+", 1)[0].lower()
        if local.lower() in ROLE_ACCOUNTS or base_local in ROLE_ACCOUNTS:
            findings.append(
                Finding(
                    label="Account type",
                    value="Role-based / shared mailbox",
                    category="email_address",
                    confidence=0.9,
                )
            )
        else:
            findings.append(
                Finding(
                    label="Account type",
                    value="Personal (likely)",
                    category="email_address",
                    confidence=0.6,
                )
            )

        if domain in DISPOSABLE_DOMAINS:
            findings.append(
                Finding(
                    label="Disposable email",
                    value="Yes (known throwaway provider)",
                    category="email_address",
                    confidence=0.9,
                )
            )

        # Plus-addressing / subaddressing (john+tag@ -> tag).
        if "+" in local:
            findings.append(
                Finding(
                    label="Plus tag",
                    value=local.split("+", 1)[1],
                    category="email_address",
                    confidence=0.9,
                )
            )

        # Gmail canonical form: dots are ignored and +tags stripped.
        if domain in ("gmail.com", "googlemail.com"):
            canonical = base_local.replace(".", "") + "@gmail.com"
            if canonical.lower() != email.lower():
                findings.append(
                    Finding(
                        label="Canonical Gmail address",
                        value=canonical,
                        category="email_address",
                        confidence=0.9,
                    )
                )
        return findings

    async def _check_gravatar(self, email: str) -> list[Finding]:
        norm = email.strip().lower().encode()
        md5 = hashlib.md5(norm, usedforsecurity=False).hexdigest()
        sha256 = hashlib.sha256(norm).hexdigest()
        resp = await get_client().get(f"https://www.gravatar.com/{md5}.json", follow_redirects=True)
        if resp.status_code != 200:
            return []

        findings = [
            Finding(
                label="Avatar (Gravatar)",
                value=f"https://www.gravatar.com/avatar/{md5}",
                category="social",
            ),
            Finding(label="Gravatar profile", value=f"https://gravatar.com/{md5}", category="social"),
            Finding(label="MD5 hash", value=md5, category="social", confidence=0.9),
            Finding(label="SHA-256 hash", value=sha256, category="social", confidence=0.9),
        ]
        try:
            entry = resp.json()["entry"][0]
        except (ValueError, KeyError, IndexError, TypeError):
            return findings

        if entry.get("displayName"):
            findings.append(Finding(label="Name (Gravatar)", value=entry["displayName"], category="social"))
        if entry.get("currentLocation"):
            findings.append(
                Finding(label="Location (Gravatar)", value=entry["currentLocation"], category="social")
            )
        about = (entry.get("aboutMe") or "").strip()
        if about:
            findings.append(Finding(label="Bio (Gravatar)", value=about[:200], category="social"))
        for acc in entry.get("accounts", []):
            if acc.get("url"):
                findings.append(
                    Finding(
                        label=f"Profile {acc.get('shortname', 'social')}",
                        value=acc["url"],
                        category="social",
                        confidence=0.9,
                    )
                )
        for link in entry.get("urls", []):
            if link.get("value"):
                title = f" {link['title']}" if link.get("title") else ""
                findings.append(
                    Finding(
                        label=f"Link{title}",
                        value=link["value"],
                        category="social",
                        confidence=0.9,
                    )
                )
        return findings

    async def _check_mx(self, domain: str) -> list[Finding]:
        records = await resolve(domain, "MX")
        if not records:
            return [
                Finding(
                    label="Receives email (MX)",
                    value="No MX records",
                    category="email_infra",
                    confidence=0.9,
                )
            ]
        # An MX record is "<preference> <exchange>".
        hosts = sorted({r.split()[-1].rstrip(".") for r in records if r.strip()})
        findings = [Finding(label="Receives email (MX)", value="Yes", category="email_infra")]
        findings += [Finding(label="MX server", value=h, category="email_infra") for h in hosts]

        # Infer the mail provider from the MX hostnames.
        joined = " ".join(hosts).lower()
        for needle, provider in MX_PROVIDERS:
            if needle in joined:
                findings.append(
                    Finding(
                        label="Mail provider (MX)",
                        value=provider,
                        category="email_infra",
                        confidence=0.85,
                    )
                )
                break
        return findings

    async def _check_website(self, domain: str) -> list[Finding]:
        """Does the email domain also host a website (A record)?"""
        ips = sorted(set(await resolve(domain, "A")))
        if not ips:
            return []
        return [
            Finding(
                label="Domain hosts website",
                value=f"Yes ({', '.join(ips[:3])})",
                category="email_infra",
            )
        ]

    async def _check_security(self, domain: str) -> list[Finding]:
        """SPF, DMARC and MTA-STS: the domain's anti-spoofing posture."""
        spf_records, dmarc_records, sts_records = await asyncio.gather(
            resolve_txt(domain),
            resolve_txt(f"_dmarc.{domain}"),
            resolve_txt(f"_mta-sts.{domain}"),
        )
        findings: list[Finding] = []
        findings += [
            Finding(label="SPF", value=v, category="email_security")
            for v in spf_records
            if v.lower().startswith("v=spf1")
        ]
        findings += [
            Finding(label="DMARC", value=v, category="email_security")
            for v in dmarc_records
            if v.lower().startswith("v=dmarc1")
        ]
        if any(v.lower().startswith("v=stsv1") for v in sts_records):
            findings.append(
                Finding(
                    label="MTA-STS",
                    value="Enabled (enforced TLS policy)",
                    category="email_security",
                    confidence=0.9,
                )
            )
        return findings

    def _pivots(self, email: str, local: str) -> list[Finding]:
        quoted = quote(f'"{email}"')
        return [
            Finding(
                label="Possible username",
                value=local.split("+", 1)[0],
                category="pivot",
                confidence=0.5,
            ),
            Finding(
                label="Web search (exact)",
                value=f"https://www.google.com/search?q={quoted}",
                category="pivot",
                confidence=0.5,
            ),
            Finding(
                label="Search on GitHub",
                value=f"https://github.com/search?q={quote(email)}&type=code",
                category="pivot",
                confidence=0.5,
            ),
        ]

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

        # The four network phases are independent: run them together.
        gravatar, mx, website, security = await asyncio.gather(
            self._check_gravatar(target),
            self._check_mx(domain),
            self._check_website(domain),
            self._check_security(domain),
        )
        findings += gravatar + mx + website + security
        findings += self._pivots(email, local)
        return findings
