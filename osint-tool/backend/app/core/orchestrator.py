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
from . import cache, history


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
        # A module runs if it supports the type AND is available. Free modules
        # are always available; key-based ones only when their key is set.
        return [
            m for m in self.modules
            if m.supports(target_type) and m.is_available()
        ]

    async def scan(self, target: str, forced_type: str | None = None) -> ScanResponse:
        target = target.strip()
        target_type = self._resolve_type(target, forced_type)

        # Serve from cache if we scanned the same target recently.
        cache_key = f"scan:{target_type.value}:{target.lower()}"
        cached = cache.get(cache_key)
        if cached:
            cached["cached"] = True
            return ScanResponse(**cached)

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

        response = ScanResponse(
            target=target,
            target_type=target_type,
            results=list(results),
            correlations=correlations,
            total_elapsed_ms=elapsed,
        )

        # Persist to history and cache (both fail safe / no-ops if unavailable).
        payload = response.model_dump(mode="json")
        history.save(payload)
        cache.set(cache_key, payload)
        return response
