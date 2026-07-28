"""
Structured application logging.

The codebase previously had no application logging at all: failures in the
cache, the history store and several parsers were swallowed by bare
`except Exception: pass`, which made them undebuggable. Every one of those
sites now logs through this module.

Output is human-readable by default and JSON when LOG_JSON=true (useful when
shipping logs to a collector).
"""

import logging
import sys
from typing import Any

import structlog

from .config import settings

_configured = False


def configure_logging() -> None:
    """Configure structlog + stdlib logging once per process."""
    global _configured
    if _configured:
        return
    _configured = True

    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if settings.log_json
        else structlog.dev.ConsoleRenderer(colors=False)
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    configure_logging()
    return structlog.get_logger(name)
