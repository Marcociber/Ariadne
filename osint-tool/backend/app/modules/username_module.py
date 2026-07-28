"""
Username module based on Maigret (free, no API key required).

Maigret checks the existence of a profile across hundreds of platforms
with real detection (response parsing, not just HTTP status), which
greatly reduces false positives compared to naive heuristics.

Design notes:
    - The site database is loaded LAZILY, on the first username scan, and
      then reused. It used to be loaded at module import, which delayed
      every backend start-up and held the data in memory even when no
      username was ever scanned.
    - Maigret is an optional runtime dependency: if it is not installed the
      module reports a clear error instead of preventing the app from
      importing at all.
    - The site count is configurable globally (MAIGRET_TOP_SITES) and per
      scan (`max_sites`), because this single number drives the perceived
      latency of the whole application.
"""

import asyncio
import logging

from ..core.base import OSINTModule, register
from ..core.config import settings
from ..core.context import get_options
from ..core.logging import get_logger
from ..core.models import Finding, TargetType

log = get_logger("username")

# Silence Maigret's internal logger (it's very verbose).
_maigret_logger = logging.getLogger("maigret")
_maigret_logger.setLevel(logging.CRITICAL)

_db = None
_sites_cache: dict[int, dict] = {}
_load_lock = asyncio.Lock()


def _load_sites_blocking(top: int) -> dict:
    """Load (once) and slice the Maigret site database. Blocking on purpose."""
    global _db
    if _db is None:
        import os

        import maigret
        from maigret import MaigretDatabase

        db_path = os.path.join(os.path.dirname(maigret.__file__), "resources", "data.json")
        _db = MaigretDatabase().load_from_path(db_path)
        log.info("username.database_loaded", path=db_path)
    if top not in _sites_cache:
        # Exclude disabled sites to avoid wasting time on them.
        _sites_cache[top] = _db.ranked_sites_dict(top=top, disabled=False)
    return _sites_cache[top]


@register
class UsernameModule(OSINTModule):
    name = "username"
    supported_types = [TargetType.USERNAME]

    @property
    def timeout(self) -> float:  # type: ignore[override]
        # The slowest module by design: it fans out to dozens of sites. Give
        # it almost the whole scan budget rather than the default ceiling.
        return max(30.0, settings.scan_timeout - 5)

    def _site_count(self) -> int:
        override = get_options().max_sites
        top = override or settings.maigret_top_sites
        return max(1, min(top, settings.maigret_max_sites))

    async def _run(self, target: str) -> list[Finding]:
        try:
            from maigret import search as maigret_search
        except ImportError as exc:  # pragma: no cover - depends on the install
            raise RuntimeError(
                "Maigret is not installed; the username module is unavailable "
                "(install it with `pip install maigret`)"
            ) from exc

        top = self._site_count()
        async with _load_lock:
            sites = await asyncio.to_thread(_load_sites_blocking, top)

        results = await maigret_search(
            username=target,
            site_dict=sites,
            logger=_maigret_logger,
            timeout=settings.maigret_timeout,
            no_progressbar=True,
        )

        profiles: list[Finding] = []
        for site_name, data in results.items():
            status = data.get("status")
            if status is None or not status.is_found():
                continue
            url = data.get("url_user") or data.get("url_main") or ""
            profiles.append(
                Finding(
                    label=f"Profile {site_name}",
                    value=url,
                    category="social",
                    confidence=0.95,
                )
            )

        # Sort alphabetically by platform for stable output.
        profiles.sort(key=lambda f: f.label.lower())

        findings: list[Finding] = []
        if profiles:
            findings.append(
                Finding(
                    label="Profiles found",
                    value=f"{len(profiles)} (of {len(sites)} sites checked)",
                    category="social",
                )
            )
        findings += profiles
        return findings
