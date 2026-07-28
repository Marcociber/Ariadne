"""
Have I Been Pwned module (OPTIONAL — requires an API key).

Checks whether an email address appears in known data breaches.

Enable it by setting HIBP_API_KEY in the environment (or backend/.env).
Without the key the module is skipped automatically
(requires_key = True + is_available()).

Every non-200 response is now reported with its meaning: a 429 (rate limit)
or a 401 (bad key) used to return an empty list, which is indistinguishable
from "this address appears in no breach" — the opposite conclusion.
"""

from ..core.base import OSINTModule, register
from ..core.config import settings
from ..core.models import Finding, TargetType
from ..core.net import get_client


@register
class HIBPModule(OSINTModule):
    name = "hibp"
    supported_types = [TargetType.EMAIL]
    requires_key = True

    def _key(self) -> str | None:
        return settings.hibp_api_key

    def is_available(self) -> bool:
        return bool(self._key())

    async def _run(self, target: str) -> list[Finding]:
        key = self._key()
        if not key:
            return []

        resp = await get_client().get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
            headers={"hibp-api-key": key, "User-Agent": "ariadne-osint"},
            params={"truncateResponse": "false"},
            timeout=15.0,
        )

        if resp.status_code == 404:
            return [Finding(label="Breaches", value="No breaches found ✅", category="hibp")]
        if resp.status_code == 429:
            retry_after = resp.headers.get("retry-after", "?")
            return [
                Finding(
                    label="Breach lookup",
                    value=f"Rate limited by HIBP — retry after {retry_after}s (result unknown)",
                    category="hibp",
                    confidence=0.9,
                )
            ]
        if resp.status_code in (401, 403):
            return [
                Finding(
                    label="Breach lookup",
                    value="HIBP rejected the API key (check HIBP_API_KEY)",
                    category="hibp",
                    confidence=0.9,
                )
            ]
        if resp.status_code != 200:
            return [
                Finding(
                    label="Breach lookup",
                    value=f"Unexpected HIBP response ({resp.status_code}); result unknown",
                    category="hibp",
                    confidence=0.8,
                )
            ]

        breaches = resp.json()
        findings = [Finding(label="Breaches found", value=str(len(breaches)), category="hibp")]
        for b in breaches:
            title = b.get("Title") or b.get("Name", "?")
            date = b.get("BreachDate", "")
            classes = ", ".join((b.get("DataClasses") or [])[:5])
            findings.append(
                Finding(
                    label=f"Breach: {title}",
                    value=f"{date} — {classes}".strip(" —"),
                    category="hibp",
                    confidence=0.95,
                )
            )
        return findings
