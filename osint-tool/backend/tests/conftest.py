"""
Shared test configuration.

The environment is set BEFORE anything imports `app`, because the settings
object is built at import time. This keeps the suite hermetic: no scan ever
writes to the developer's real history database, and rate limits do not make
tests flaky.
"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="ariadne-tests-")

os.environ.update(
    {
        "HISTORY_DB": os.path.join(_TMP, "history.db"),
        "REDIS_URL": "",  # cache disabled: tests must not need Redis
        "RATE_LIMIT": "10000/minute",
        "SCAN_RATE_LIMIT": "10000/minute",
        "CORS_ORIGINS": "*",
        "API_KEY": "",
        "SCAN_TIMEOUT": "15",
        "MODULE_TIMEOUT": "10",
        "WHOIS_TIMEOUT": "5",
        "LOG_LEVEL": "CRITICAL",
        "MAIGRET_TOP_SITES": "5",
    }
)

import pytest  # noqa: E402


@pytest.fixture
def anyio_backend():
    return "asyncio"
