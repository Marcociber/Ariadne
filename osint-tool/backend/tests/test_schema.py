"""
Property-based tests against the OpenAPI schema FastAPI already generates.

Only the read-only endpoints are exercised. `/scan` is deliberately excluded:
Schemathesis would generate arbitrary targets and the modules would go out to
the real network, which would make the suite slow, flaky and impolite to
third-party services.

FastAPI emits OpenAPI 3.1 while Schemathesis 3.x only reads 3.0, so the
version marker is downgraded for the test. The endpoints covered here use no
3.1-only constructs, so the documents are equivalent.
"""

import pytest

schemathesis = pytest.importorskip("schemathesis")

from app.main import app  # noqa: E402

_raw = {**app.openapi(), "openapi": "3.0.2"}
schema = schemathesis.from_dict(_raw, app=app, endpoint="^/(health|modules)$")


@schema.parametrize()
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_read_only_endpoints_match_their_schema(case):
    case.validate_response(case.call_asgi())
