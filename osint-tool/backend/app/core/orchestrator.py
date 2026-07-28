"""
Orchestrator: selects modules that support the target type and runs them IN
PARALLEL. If a module fails or is slow it does not block the others (each
`run()` already isolates its own errors and enforces its own timeout).

What this layer adds on top of the first version:

  * a GLOBAL deadline. Modules still running when SCAN_TIMEOUT expires are
    cancelled and reported as errors, so the HTTP request always returns and
    the user keeps the partial results instead of losing everything.
  * STREAMING. `stream()` yields each module result the moment it finishes,
    which is what the SSE endpoint serves — the data was already produced
    independently per module, only the transport was missing.
  * non-blocking persistence: history writes and cache writes no longer run
    synchronously inside the coroutine.
  * a cache key that includes the ACTIVE MODULE SET, so adding an API key
    stops serving a stale result computed without that module.
  * a concurrency limit, because a single username scan fans out to ~150
    outbound requests.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import AsyncIterator

from . import cache, history
from .base import REGISTRY, OSINTModule
from .config import settings
from .context import ScanOptions, reset_options, set_options
from .correlation import correlate
from .detector import Detection, analyze
from .logging import get_logger
from .models import Correlation, ModuleResult, ModuleStatus, ScanResponse, TargetType

log = get_logger("orchestrator")


class Orchestrator:
    def __init__(self) -> None:
        # Lazy import: ensures all plugins have been registered (via @register)
        # before instantiating them, regardless of import order of callers.
        import app.modules  # noqa: F401

        # Instantiate all registered modules once.
        self.modules: list[OSINTModule] = [cls() for cls in REGISTRY]
        self._gate = asyncio.Semaphore(max(1, settings.max_concurrent_scans))

    # ---------------------------------------------------------------- setup
    def _resolve(self, target: str, forced_type: str | None) -> Detection:
        """Respect the type chosen by the user; otherwise autodetect.

        The target is normalized either way, so a pasted URL works even when
        the user forces `domain`.
        """
        detection = analyze(target)
        if forced_type and forced_type.lower() != "auto":
            try:
                forced = TargetType(forced_type.lower())
            except ValueError:
                return detection  # invalid value -> fall back to autodetection
            if forced is not TargetType.UNKNOWN:
                return Detection(detection.target, forced)
        return detection

    def _select(self, target_type: TargetType) -> list[OSINTModule]:
        # A module runs if it supports the type AND is available. Free modules
        # are always available; key-based ones only when their key is set.
        return [m for m in self.modules if m.supports(target_type) and m.is_available()]

    def _skipped(self, target_type: TargetType) -> list[str]:
        """Modules that would apply but have no API key configured."""
        return [m.name for m in self.modules if m.supports(target_type) and not m.is_available()]

    def _cache_key(self, target: str, target_type: TargetType, modules: list[OSINTModule]) -> str:
        # The module set is part of the identity of a result: without it, a
        # scan cached before a key was added keeps being served afterwards.
        digest = hashlib.sha256(",".join(sorted(m.name for m in modules)).encode()).hexdigest()[:10]
        return f"scan:{target_type.value}:{target.lower()}:{digest}"

    # ------------------------------------------------------------ execution
    async def _iter_module_results(
        self, target: str, target_type: TargetType, modules: list[OSINTModule]
    ) -> AsyncIterator[ModuleResult]:
        """Yield each module result as soon as it is ready, under a deadline."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + settings.scan_timeout
        tasks: dict[asyncio.Task, OSINTModule] = {
            asyncio.create_task(m.run(target, target_type), name=f"scan:{m.name}"): m for m in modules
        }
        pending = set(tasks)

        while pending:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            done, pending = await asyncio.wait(
                pending, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                yield task.result()

        # Whatever is still running when the global deadline hits is cancelled
        # and reported, so the caller sees why a source is missing.
        for task in pending:
            task.cancel()
            module = tasks[task]
            log.warning("scan.module_deadline", module=module.name, target=target)
            yield ModuleResult(
                module=module.name,
                target=target,
                target_type=target_type,
                status=ModuleStatus.ERROR,
                error=f"Cancelled: the scan deadline of {settings.scan_timeout}s was reached",
            )
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def _build_response(
        self,
        detection: Detection,
        results: list[ModuleResult],
        elapsed_ms: int,
        skipped: list[str],
    ) -> ScanResponse:
        correlations: list[Correlation] = correlate(results)
        message = detection.reason
        if message is None and not results:
            message = (
                f"No source supports the type '{detection.type.value}' yet."
                if detection.type is not TargetType.UNKNOWN
                else None
            )
        return ScanResponse(
            target=detection.target,
            target_type=detection.type,
            results=results,
            correlations=correlations,
            total_elapsed_ms=elapsed_ms,
            message=message,
            skipped_modules=skipped,
        )

    # ---------------------------------------------------------------- entry
    async def scan(
        self,
        target: str,
        forced_type: str | None = None,
        *,
        refresh: bool = False,
        options: ScanOptions | None = None,
    ) -> ScanResponse:
        detection = self._resolve(target, forced_type)
        modules = self._select(detection.type)
        skipped = self._skipped(detection.type)
        key = self._cache_key(detection.target, detection.type, modules)

        if refresh:
            await cache.delete(key)
        else:
            cached = await cache.get(key)
            if cached:
                cached["cached"] = True
                log.info("scan.cache_hit", target=detection.target, type=detection.type.value)
                return ScanResponse(**cached)

        token = set_options(options or ScanOptions())
        start = time.perf_counter()
        try:
            async with self._gate:
                results = [
                    r async for r in self._iter_module_results(detection.target, detection.type, modules)
                ]
        finally:
            reset_options(token)

        elapsed = int((time.perf_counter() - start) * 1000)
        response = self._build_response(detection, results, elapsed, skipped)
        log.info(
            "scan.done",
            target=detection.target,
            type=detection.type.value,
            modules=len(results),
            elapsed_ms=elapsed,
        )

        payload = response.model_dump(mode="json")
        # Persistence must not sit on the critical path of the response.
        asyncio.create_task(self._persist(key, payload))  # noqa: RUF006
        return response

    async def _persist(self, key: str, payload: dict) -> None:
        """Store the scan in history and cache. Both fail safe."""
        try:
            await history.save_async(payload)
            await cache.set(key, payload)
        except Exception as exc:
            log.warning("scan.persist_failed", error=str(exc))

    async def stream(
        self,
        target: str,
        forced_type: str | None = None,
        *,
        refresh: bool = False,
        options: ScanOptions | None = None,
    ) -> AsyncIterator[tuple[str, dict]]:
        """Yield `(event_name, payload)` pairs as the scan progresses.

        Events: `start`, `module` (once per source), `done`.
        """
        detection = self._resolve(target, forced_type)
        modules = self._select(detection.type)
        skipped = self._skipped(detection.type)
        key = self._cache_key(detection.target, detection.type, modules)

        if refresh:
            await cache.delete(key)
        else:
            cached = await cache.get(key)
            if cached:
                cached["cached"] = True
                response = ScanResponse(**cached)
                yield (
                    "start",
                    {
                        "target": response.target,
                        "target_type": response.target_type.value,
                        "modules": [r.module for r in response.results],
                        "cached": True,
                    },
                )
                for result in response.results:
                    yield "module", result.model_dump(mode="json")
                yield "done", response.model_dump(mode="json")
                return

        yield (
            "start",
            {
                "target": detection.target,
                "target_type": detection.type.value,
                "modules": [m.name for m in modules],
                "skipped_modules": skipped,
                "message": detection.reason,
                "cached": False,
            },
        )

        token = set_options(options or ScanOptions())
        start = time.perf_counter()
        results: list[ModuleResult] = []
        try:
            async with self._gate:
                async for result in self._iter_module_results(detection.target, detection.type, modules):
                    results.append(result)
                    yield "module", result.model_dump(mode="json")
        finally:
            reset_options(token)

        elapsed = int((time.perf_counter() - start) * 1000)
        response = self._build_response(detection, results, elapsed, skipped)
        payload = response.model_dump(mode="json")
        await self._persist(key, payload)
        yield "done", payload
