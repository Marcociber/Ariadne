"""
Have I Been Pwned module (OPTIONAL — requires an API key).

Checks whether an email address appears in known data breaches.

Enable it by setting HIBP_API_KEY in the environment (.env). Without the key
the module is skipped automatically (requires_key = True + is_available()).
"""
import os

import httpx

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType


@register
class HIBPModule(OSINTModule):
    name = "hibp"
    supported_types = [TargetType.EMAIL]
    requires_key = True

    def _key(self) -> str | None:
        return os.getenv("HIBP_API_KEY")

    def is_available(self) -> bool:
        return bool(self._key())

    async def _run(self, target: str) -> list[Finding]:
        key = self._key()
        if not key:
            return []

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
        headers = {"hibp-api-key": key, "User-Agent": "ariadne-osint"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers, params={"truncateResponse": "false"})

        if resp.status_code == 404:
            return [Finding(label="Breaches", value="No breaches found ✅", category="hibp")]
        if resp.status_code != 200:
            return []

        breaches = resp.json()
        findings = [Finding(label="Breaches found", value=str(len(breaches)), category="hibp")]
        for b in breaches:
            title = b.get("Title") or b.get("Name", "?")
            date = b.get("BreachDate", "")
            classes = ", ".join((b.get("DataClasses") or [])[:5])
            findings.append(Finding(
                label=f"Breach: {title}",
                value=f"{date} — {classes}".strip(" —"),
                category="hibp", confidence=0.95,
            ))
        return findings
