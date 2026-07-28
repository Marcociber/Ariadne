"""
Common interface for all OSINT modules (plugin architecture).

To add a new source:
    1. Create a class that inherits from OSINTModule.
    2. Declare `name` and `supported_types`.
    3. Implement `_run(target)`.
    4. Register the class with @register.

You do not need to modify core or the orchestrator.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod

from .config import settings
from .logging import get_logger
from .models import Finding, ModuleResult, ModuleStatus, TargetType

log = get_logger("module")

# Global registry of available modules.
REGISTRY: list[type[OSINTModule]] = []


def register(cls: type[OSINTModule]) -> type[OSINTModule]:
    """Decorator that registers a module automatically."""
    REGISTRY.append(cls)
    return cls


class OSINTModule(ABC):
    name: str = "base"
    supported_types: list[TargetType] = []
    # If the module requires an API key, mark it here so it can be
    # cleanly skipped when the key is not configured.
    requires_key: bool = False
    # Per-module ceiling in seconds. None means "use MODULE_TIMEOUT".
    # Slow-by-design modules (Maigret fans out to ~150 sites) raise it.
    timeout: float | None = None

    def supports(self, target_type: TargetType) -> bool:
        return target_type in self.supported_types

    def is_available(self) -> bool:
        """Whether this module can run right now.

        Free modules are always available. Key-based modules override this to
        return True only when their API key is configured, so the orchestrator
        can include them dynamically instead of always skipping them.
        """
        return not self.requires_key

    async def run(self, target: str, target_type: TargetType) -> ModuleResult:
        """Wrap `_run` with timing, a hard timeout and error capture.

        A failure in one module must NEVER bring down the whole scan, and a
        source that never answers must not keep the HTTP request open: without
        the timeout a hung WHOIS server blocked the entire scan indefinitely.
        """
        start = time.perf_counter()
        limit = self.timeout if self.timeout is not None else settings.module_timeout
        try:
            findings = await asyncio.wait_for(self._run(target), timeout=limit)
            status = ModuleStatus.OK if findings else ModuleStatus.EMPTY
            result = ModuleResult(
                module=self.name,
                target=target,
                target_type=target_type,
                status=status,
                findings=findings,
            )
        except TimeoutError:
            log.warning("module.timeout", module=self.name, target=target, limit=limit)
            result = ModuleResult(
                module=self.name,
                target=target,
                target_type=target_type,
                status=ModuleStatus.ERROR,
                error=f"Timed out after {limit:g}s",
            )
        except Exception as exc:
            log.warning(
                "module.failed",
                module=self.name,
                target=target,
                error=f"{type(exc).__name__}: {exc}",
            )
            result = ModuleResult(
                module=self.name,
                target=target,
                target_type=target_type,
                status=ModuleStatus.ERROR,
                error=f"{type(exc).__name__}: {exc}",
            )
        result.elapsed_ms = int((time.perf_counter() - start) * 1000)
        log.debug(
            "module.done",
            module=self.name,
            status=result.status.value,
            findings=len(result.findings),
            elapsed_ms=result.elapsed_ms,
        )
        return result

    @abstractmethod
    async def _run(self, target: str) -> list[Finding]:
        """Source-specific logic. Returns a list of findings."""
        ...
