"""
Wayback Machine module (free, no API key required):
    - Historical footprint of a domain from the Internet Archive's CDX API:
      first and last capture dates, plus a link to browse every archived
      snapshot.

The Internet Archive is fully open (no key, no auth). Great for spotting
when a site first appeared, whether it is still archived, and for reviewing
past versions of a page. All values come from the archive's own responses.
"""
import httpx

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType

_CDX = "http://web.archive.org/cdx/search/cdx"


def _fmt_ts(ts: str) -> str:
    """Turn a 14-digit Wayback timestamp (YYYYMMDDhhmmss) into YYYY-MM-DD."""
    if len(ts) >= 8 and ts[:8].isdigit():
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    return ts


@register
class WaybackModule(OSINTModule):
    name = "wayback"
    supported_types = [TargetType.DOMAIN]

    async def _cdx(self, client: httpx.AsyncClient, params: dict) -> list | None:
        base = {"url": params["url"], "output": "json", "fl": "timestamp,original,statuscode"}
        base.update(params)
        try:
            resp = await client.get(_CDX, params=base)
            if resp.status_code == 200:
                rows = resp.json()
                # First row is the header; drop it.
                return rows[1:] if len(rows) > 1 else []
        except (httpx.HTTPError, ValueError):
            pass
        return None

    async def _run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=20.0, headers={"User-Agent": "osint-tool"}) as client:
            first = await self._cdx(client, {"url": target, "limit": "1"})
            last = await self._cdx(client, {"url": target, "limit": "-1"})

        if first is None and last is None:
            return []  # archive unreachable
        if not first and not last:
            findings.append(Finding(label="Archived", value="No snapshots found", category="archive", confidence=0.9))
            return findings

        findings.append(Finding(label="Archived", value="Yes (Internet Archive)", category="archive"))

        if first:
            ts = first[0][0]
            findings.append(Finding(label="First snapshot", value=_fmt_ts(ts), category="archive"))
            findings.append(Finding(
                label="First snapshot (view)",
                value=f"https://web.archive.org/web/{ts}/{target}",
                category="archive", confidence=0.9))
        if last:
            ts = last[0][0]
            findings.append(Finding(label="Last snapshot", value=_fmt_ts(ts), category="archive"))
            findings.append(Finding(
                label="Last snapshot (view)",
                value=f"https://web.archive.org/web/{ts}/{target}",
                category="archive", confidence=0.9))

        findings.append(Finding(
            label="Browse all snapshots",
            value=f"https://web.archive.org/web/*/{target}",
            category="pivot", confidence=0.6))
        return findings
