"""
Core behaviours that used to be implicit: timeouts, retention, fail-safe
cache, and the cache key including the active module set.
"""

import asyncio

import pytest

from app.core import cache, history
from app.core.base import OSINTModule
from app.core.config import settings
from app.core.models import Finding, ModuleStatus, TargetType
from app.core.orchestrator import Orchestrator


class HangingModule(OSINTModule):
    name = "hanging"
    supported_types = [TargetType.DOMAIN]
    timeout = 0.2

    async def _run(self, target: str) -> list[Finding]:
        await asyncio.sleep(30)
        return []


class BrokenModule(OSINTModule):
    name = "broken"
    supported_types = [TargetType.DOMAIN]

    async def _run(self, target: str) -> list[Finding]:
        raise RuntimeError("source exploded")


class QuietModule(OSINTModule):
    name = "quiet"
    supported_types = [TargetType.DOMAIN]

    async def _run(self, target: str) -> list[Finding]:
        return []


# ------------------------------------------------------------- timeouts ---
async def test_a_hanging_module_is_cut_off():
    """Without this, one unresponsive source held the HTTP request open."""
    result = await HangingModule().run("example.com", TargetType.DOMAIN)
    assert result.status is ModuleStatus.ERROR
    assert "Timed out" in result.error
    assert result.elapsed_ms < 5000


async def test_a_failing_module_is_isolated_and_explains_itself():
    result = await BrokenModule().run("example.com", TargetType.DOMAIN)
    assert result.status is ModuleStatus.ERROR
    assert "source exploded" in result.error


async def test_an_empty_module_is_not_an_error():
    result = await QuietModule().run("example.com", TargetType.DOMAIN)
    assert result.status is ModuleStatus.EMPTY
    assert result.error is None


# ------------------------------------------------------------ cache key ---
def test_cache_key_depends_on_the_active_module_set():
    """Adding an API key must not keep serving the result computed without it."""
    orch = Orchestrator()
    modules = orch._select(TargetType.DOMAIN)
    key_all = orch._cache_key("example.com", TargetType.DOMAIN, modules)
    key_fewer = orch._cache_key("example.com", TargetType.DOMAIN, modules[:-1])
    assert key_all != key_fewer


def test_cache_key_is_case_insensitive_on_the_target():
    orch = Orchestrator()
    modules = orch._select(TargetType.DOMAIN)
    assert orch._cache_key("Example.COM", TargetType.DOMAIN, modules) == orch._cache_key(
        "example.com", TargetType.DOMAIN, modules
    )


# ---------------------------------------------------------------- cache ---
async def test_cache_is_a_no_op_without_redis():
    """Scans must keep working when the cache is unavailable."""
    assert await cache.enabled() is False
    assert await cache.get("anything") is None
    await cache.set("anything", {"a": 1})  # must not raise
    await cache.delete("anything")  # must not raise


# -------------------------------------------------------------- history ---
def test_history_enforces_the_row_limit(monkeypatch):
    """The table used to grow without bound, storing the full JSON per scan."""
    monkeypatch.setattr(settings, "history_max_rows", 5)
    before = history.count()
    for i in range(12):
        history.save(
            {
                "target": f"retention-{i}.example",
                "target_type": "domain",
                "results": [],
                "total_elapsed_ms": 1,
            }
        )
    assert history.count() <= 5
    assert before >= 0


def test_history_pagination():
    for i in range(4):
        history.save(
            {"target": f"page-{i}.example", "target_type": "domain", "results": [], "total_elapsed_ms": 1}
        )
    first = history.list_recent(limit=2, offset=0)
    second = history.list_recent(limit=2, offset=2)
    assert len(first) == 2
    assert {r["id"] for r in first}.isdisjoint({r["id"] for r in second})


def test_history_failures_are_survivable(monkeypatch):
    """A broken database must never break a scan."""
    monkeypatch.setattr(settings, "history_db", "/nonexistent-dir/nope.db")
    monkeypatch.setattr(history, "_initialized", False)
    history.save({"target": "x", "target_type": "domain", "results": [], "total_elapsed_ms": 0})
    assert history.list_recent() == []
    assert history.get(1) is None


# --------------------------------------------------------- orchestrator ---
async def test_forced_type_is_respected_and_target_normalized():
    orch = Orchestrator()
    detection = orch._resolve("https://example.com/page", "ip")
    assert detection.type is TargetType.IP
    assert detection.target == "example.com"


async def test_autodetect_when_type_is_auto():
    orch = Orchestrator()
    assert orch._resolve("torvalds", "auto").type is TargetType.USERNAME


@pytest.mark.parametrize("bogus", ["nonsense", "", "AUTO"])
async def test_bad_forced_type_falls_back_to_autodetection(bogus):
    orch = Orchestrator()
    assert orch._resolve("example.com", bogus).type is TargetType.DOMAIN
