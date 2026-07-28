"""
API contract tests, driven through the ASGI app (no server, no network).
"""

import httpx
import pytest

from app.core import history
from app.core.config import settings
from app.main import app


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_health_is_open(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_modules_endpoint_lists_every_plugin(client):
    resp = await client.get("/modules")
    assert resp.status_code == 200
    names = {m["name"] for m in resp.json()}
    assert {"dns", "whois", "rdap", "crtsh", "tls", "http", "robots", "phone", "ip"} <= names


async def test_key_based_modules_report_availability(client):
    modules = {m["name"]: m for m in (await client.get("/modules")).json()}
    assert modules["shodan"]["requires_key"] is True
    assert modules["shodan"]["available"] is bool(settings.shodan_api_key)


# ---------------------------------------------------------------- input ---
@pytest.mark.parametrize(
    "body",
    [
        {},  # target missing
        {"target": ""},  # blank
        {"target": "   "},  # whitespace only
        {"target": "x" * 500},  # over max_target_length
        {"target": "a.com", "target_type": "not-a-type"},
        {"target": "a.com", "max_sites": 0},
        {"target": "a.com", "max_sites": 99999},
    ],
)
async def test_invalid_requests_are_rejected_with_422(client, body):
    """These used to be silently ignored or accepted."""
    resp = await client.post("/scan", json=body)
    assert resp.status_code == 422


async def test_auto_is_accepted_as_target_type(client):
    resp = await client.post("/scan", json={"target": "+34612345678", "target_type": "auto"})
    assert resp.status_code == 200
    assert resp.json()["target_type"] == "phone"


async def test_unknown_target_explains_itself(client):
    resp = await client.post("/scan", json={"target": "!!!!!!"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["target_type"] == "unknown"
    assert body["message"]


async def test_offline_scan_returns_findings(client):
    resp = await client.post("/scan", json={"target": "+34612345678"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["target_type"] == "phone"
    assert body["results"][0]["module"] == "phone"
    assert body["results"][0]["findings"]
    assert "total_elapsed_ms" in body


# ------------------------------------------------------------------ auth ---
async def test_api_key_is_enforced_when_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "s3cret")
    assert (await client.get("/modules")).status_code == 401
    assert (await client.get("/modules", headers={"X-API-Key": "wrong"})).status_code == 401
    assert (await client.get("/modules", headers={"X-API-Key": "s3cret"})).status_code == 200
    # Health stays open so container healthchecks keep working.
    assert (await client.get("/health")).status_code == 200


# --------------------------------------------------------------- history ---
async def test_history_roundtrip(client):
    history.save(
        {
            "target": "history-test.example",
            "target_type": "domain",
            "results": [
                {
                    "module": "dns",
                    "target": "history-test.example",
                    "target_type": "domain",
                    "status": "ok",
                    "findings": [{"label": "Record A", "value": "203.0.113.1", "category": "dns"}],
                }
            ],
            "total_elapsed_ms": 5,
        }
    )
    listing = (await client.get("/history?limit=5")).json()
    assert listing["total"] >= 1
    assert "items" in listing and "offset" in listing

    entry = next(i for i in listing["items"] if i["target"] == "history-test.example")
    assert entry["findings_count"] == 1

    detail = await client.get(f"/history/{entry['id']}")
    assert detail.status_code == 200
    assert detail.json()["target"] == "history-test.example"

    assert (await client.delete(f"/history/{entry['id']}")).status_code == 200
    assert (await client.get(f"/history/{entry['id']}")).status_code == 404


async def test_missing_history_entry_is_404(client):
    assert (await client.get("/history/999999")).status_code == 404


async def test_history_pagination_is_validated(client):
    assert (await client.get("/history?limit=0")).status_code == 422
    assert (await client.get("/history?limit=99999")).status_code == 422
    assert (await client.get("/history?offset=-1")).status_code == 422


# ---------------------------------------------------------------- schema ---
async def test_openapi_schema_is_generated(client):
    schema = (await client.get("/openapi.json")).json()
    assert schema["openapi"].startswith("3.")
    for path in ("/health", "/modules", "/scan", "/scan/stream", "/history"):
        assert path in schema["paths"]
