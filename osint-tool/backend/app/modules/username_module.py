"""
Username module based on Maigret (free, no API key required).

Maigret checks the existence of a profile across hundreds of platforms
with real detection (response parsing, not just HTTP status), which
greatly reduces false positives compared to naive heuristics.

Design notes:
    - The site database is loaded ONCE (at module import) and reused
        across scans.
    - It is limited to the `TOP_SITES` highest-ranked sites for speed;
        configurable via environment variable.
    - Maigret is async and fits naturally into the orchestrator.
"""
import logging
import os

import maigret
from maigret import search as maigret_search
from maigret import MaigretDatabase

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType

# Number of top-ranked sites to check. Less = faster.
TOP_SITES = int(os.getenv("MAIGRET_TOP_SITES", "150"))
# Timeout per site in seconds.
SITE_TIMEOUT = int(os.getenv("MAIGRET_TIMEOUT", "10"))

# Silence Maigret's internal logger (it's very verbose).
_logger = logging.getLogger("maigret")
_logger.setLevel(logging.CRITICAL)

# Load the site DB once at module import.
_pkg_dir = os.path.dirname(maigret.__file__)
_db_path = os.path.join(_pkg_dir, "resources", "data.json")
_DB = MaigretDatabase().load_from_path(_db_path)
# Exclude disabled sites to avoid wasting time on them.
_SITES = _DB.ranked_sites_dict(top=TOP_SITES, disabled=False)


@register
class UsernameModule(OSINTModule):
    name = "username"
    supported_types = [TargetType.USERNAME]

    async def _run(self, target: str) -> list[Finding]:
        results = await maigret_search(
            username=target,
            site_dict=_SITES,
            logger=_logger,
            timeout=SITE_TIMEOUT,
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

        # Ordenar alfabéticamente por plataforma para salida estable.
        profiles.sort(key=lambda f: f.label.lower())

        findings: list[Finding] = []
        if profiles:
            findings.append(Finding(
                label="Profiles found",
                value=f"{len(profiles)} (of {len(_SITES)} sites checked)",
                category="social"))
        findings += profiles
        return findings
