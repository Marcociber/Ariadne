"""
Orchestrator: selects modules that support the target type
and runs them IN PARALLEL using asyncio.gather.

If a module fails or is slow, it does not block the others (each
run() already isolates its own errors).
"""
import asyncio
import time

from .base import OSINTModule, REGISTRY
from .detector import detect_type
from .models import ScanResponse, TargetType
from .correlation import correlate


class Orchestrator:
    def __init__(self) -> None:
        # Lazy import: ensures all plugins have been registered (via @register)
        # before instantiating them, regardless of import order of callers.
        import app.modules  # noqa: F401
        # Instantiate all registered modules once.
        self.modules: list[OSINTModule] = [cls() for cls in REGISTRY]

    def _resolve_type(self, target: str, forced_type: str | None) -> TargetType:
        """Respect the type chosen by the user; otherwise autodetect."""
        if forced_type and forced_type.lower() != "auto":
            try:
                return TargetType(forced_type.lower())
            except ValueError:
                pass  # invalid value -> fall back to autodetection
        return detect_type(target)

    def _select(self, target_type: TargetType) -> list[OSINTModule]:
        return [
            m for m in self.modules
            if m.supports(target_type) and not m.requires_key
        ]

    async def scan(self, target: str, forced_type: str | None = None) -> ScanResponse:
        target = target.strip()
        target_type = self._resolve_type(target, forced_type)
        start = time.perf_counter()

        modules = self._select(target_type)
        if modules:
            results = await asyncio.gather(
                *(m.run(target, target_type) for m in modules)
            )
        else:
            results = []

        correlations = correlate(results)
        elapsed = int((time.perf_counter() - start) * 1000)

        return ScanResponse(
            target=target,
            target_type=target_type,
            results=list(results),
            correlations=correlations,
            total_elapsed_ms=elapsed,
        )
