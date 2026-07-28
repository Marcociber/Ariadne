"""
Per-scan options, carried without changing the plugin contract.

Modules implement `_run(target)` and nothing else — that simplicity is the
point of the plugin architecture and is documented in the README. When a
caller needs to tune one module (for example asking the username module to
check fewer sites so the scan returns faster), the option travels in a
context variable instead of being threaded through every signature.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanOptions:
    """Options a caller may attach to a single scan."""

    # Overrides MAIGRET_TOP_SITES for this scan only (None = configured default).
    max_sites: int | None = None


_options: ContextVar[ScanOptions] = ContextVar("scan_options", default=ScanOptions())


def set_options(options: ScanOptions) -> Token[ScanOptions]:
    """Bind options to the current task. Returns the token to reset with."""
    return _options.set(options)


def reset_options(token: Token[ScanOptions]) -> None:
    _options.reset(token)


def get_options() -> ScanOptions:
    return _options.get()
