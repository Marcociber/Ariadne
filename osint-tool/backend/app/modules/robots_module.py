"""
robots.txt / sitemap module (free, no API key required).

`robots.txt` is published by the site itself and routinely names paths the
owner would rather not have indexed — admin panels, staging areas, internal
tools — which makes it one of the cheapest and most reliable pieces of
passive reconnaissance. The sitemap gives the size and shape of the public
site.

Nothing is crawled: exactly two well-known files are requested, through the
same SSRF guard and body-size cap as the HTTP module.
"""

import re

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType
from ..core.net import UnsafeTargetError, safe_fetch

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_SITEMAP_INDEX_RE = re.compile(r"<sitemapindex", re.I)

# Disallowed paths that are worth surfacing on their own.
_INTERESTING = (
    "admin",
    "login",
    "wp-admin",
    "backup",
    "config",
    "private",
    "internal",
    "staging",
    "dev",
    "test",
    "api",
    "phpmyadmin",
    "cgi-bin",
    ".git",
    ".env",
    "database",
    "db",
    "secret",
    "token",
    "upload",
    "tmp",
    "old",
)


@register
class RobotsModule(OSINTModule):
    name = "robots"
    supported_types = [TargetType.DOMAIN]

    async def _fetch_text(self, url: str) -> str | None:
        try:
            result = await safe_fetch(url, max_bytes=120_000)
        except UnsafeTargetError:
            raise
        except Exception:
            return None
        if result.status_code != 200:
            return None
        return result.text

    def _parse_robots(self, body: str) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        disallowed: list[str] = []
        sitemaps: list[str] = []
        agents = 0

        for raw_line in body.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "user-agent":
                agents += 1
            elif key == "disallow" and value and value != "/":
                disallowed.append(value)
            elif key == "sitemap" and value:
                sitemaps.append(value)

        findings.append(Finding(label="robots.txt", value="Present", category="web"))
        if agents:
            findings.append(
                Finding(
                    label="robots.txt user-agent rules",
                    value=str(agents),
                    category="web",
                    confidence=0.9,
                )
            )
        if disallowed:
            findings.append(
                Finding(
                    label="Disallowed paths",
                    value=str(len(disallowed)),
                    category="web",
                    confidence=0.9,
                )
            )
        # Highlight the paths that usually matter in an assessment.
        interesting = [p for p in disallowed if any(word in p.lower() for word in _INTERESTING)]
        findings += [
            Finding(
                label="Notable disallowed path",
                value=path[:120],
                category="web_security",
                confidence=0.9,
            )
            for path in dict.fromkeys(interesting[:20])
        ]
        others = list(dict.fromkeys(p for p in disallowed if p not in interesting))
        findings += [
            Finding(label="Disallowed path", value=path[:120], category="web", confidence=0.9)
            for path in others[:20]
        ]
        findings += [
            Finding(label="Sitemap declared", value=url[:200], category="web")
            for url in dict.fromkeys(sitemaps[:5])
        ]
        return findings, sitemaps

    def _parse_sitemap(self, body: str, source: str) -> list[Finding]:
        locs = _LOC_RE.findall(body)
        if not locs:
            return []
        kind = "Sitemap index" if _SITEMAP_INDEX_RE.search(body) else "Sitemap"
        findings = [
            Finding(
                label=f"{kind} ({source})",
                value=f"{len(locs)} entries",
                category="web",
                confidence=0.95,
            )
        ]
        findings += [
            Finding(label="Sitemap URL", value=loc[:200], category="web", confidence=0.9) for loc in locs[:15]
        ]
        return findings

    async def _run(self, target: str) -> list[Finding]:
        base = f"https://{target}"
        try:
            robots = await self._fetch_text(f"{base}/robots.txt")
        except UnsafeTargetError as exc:
            return [
                Finding(
                    label="robots.txt",
                    value=f"Refused: {exc}",
                    category="web_security",
                    confidence=0.9,
                )
            ]

        findings: list[Finding] = []
        declared: list[str] = []
        if robots is None:
            findings.append(
                Finding(
                    label="robots.txt",
                    value="Not published",
                    category="web",
                    confidence=0.9,
                )
            )
        else:
            parsed, declared = self._parse_robots(robots)
            findings += parsed

        # Prefer a sitemap the site declares; otherwise try the well-known path.
        sitemap_url = declared[0] if declared else f"{base}/sitemap.xml"
        try:
            sitemap = await self._fetch_text(sitemap_url)
        except UnsafeTargetError:
            sitemap = None
        if sitemap:
            findings += self._parse_sitemap(sitemap, "declared" if declared else "/sitemap.xml")
        return findings
