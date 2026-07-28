"""
Modules that talk HTTP, tested against recorded responses with respx.
No network access, deterministic results.
"""

import httpx
import pytest
import respx

from app.core.config import settings
from app.modules.crtsh_module import CrtShModule
from app.modules.github_module import GitHubModule
from app.modules.hibp_module import HIBPModule
from app.modules.rdap_module import RDAPModule
from app.modules.wayback_module import WaybackModule


def by_label(findings, label):
    return [f.value for f in findings if f.label == label]


# --------------------------------------------------------------- crt.sh ---
CRTSH_PAYLOAD = [
    {"name_value": "mail.ejemplo.com\nwww.ejemplo.com", "issuer_name": "C=US, O=Let's Encrypt, CN=R3"},
    {"name_value": "*.ejemplo.com", "issuer_name": "C=US, O=Let's Encrypt, CN=R3"},
    # The false positive the previous `endswith(target)` check let through.
    {"name_value": "noesejemplo.com", "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign"},
    {"name_value": "ejemplo.com", "issuer_name": "C=US, O=Let's Encrypt, CN=R3"},
]


@respx.mock
async def test_crtsh_rejects_lookalike_domains():
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, json=CRTSH_PAYLOAD))
    findings = await CrtShModule()._run("ejemplo.com")
    subdomains = by_label(findings, "Subdomain")

    assert "mail.ejemplo.com" in subdomains
    assert "www.ejemplo.com" in subdomains
    assert "noesejemplo.com" not in subdomains  # <- the regression guard
    assert "ejemplo.com" not in subdomains  # the domain is not its own subdomain
    assert by_label(findings, "Subdomains found") == ["2"]


@respx.mock
async def test_crtsh_detects_wildcards_and_issuers():
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, json=CRTSH_PAYLOAD))
    findings = await CrtShModule()._run("ejemplo.com")
    assert by_label(findings, "Wildcard certificate")
    issuers = by_label(findings, "Certificate issuer")
    assert any("Let's Encrypt" in i for i in issuers)


@respx.mock
async def test_crtsh_retries_then_gives_up_quietly():
    route = respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(502))
    assert await CrtShModule()._run("ejemplo.com") == []
    assert route.call_count == 3  # the documented retry budget


# --------------------------------------------------------------- GitHub ---
@respx.mock
async def test_github_reports_rate_limiting_instead_of_nothing():
    """403 used to look identical to 'this user does not exist'."""
    respx.get("https://api.github.com/users/torvalds").mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-reset": "1800000000"}, json={})
    )
    findings = await GitHubModule()._run("torvalds")
    assert len(findings) == 1
    assert "rate limit" in findings[0].value.lower()


@respx.mock
async def test_github_reports_a_missing_account_distinctly():
    respx.get("https://api.github.com/users/nobody").mock(return_value=httpx.Response(404, json={}))
    findings = await GitHubModule()._run("nobody")
    assert "No public account" in findings[0].value


@respx.mock
async def test_github_profile_is_parsed():
    respx.get("https://api.github.com/users/torvalds").mock(
        return_value=httpx.Response(
            200,
            json={
                "html_url": "https://github.com/torvalds",
                "type": "User",
                "name": "Linus Torvalds",
                "company": "Linux Foundation",
                "location": "Portland, OR",
                "blog": "linux.org",
                "public_repos": 7,
                "followers": 200000,
                "created_at": "2011-09-03T15:26:22Z",
            },
        )
    )
    respx.get(url__startswith="https://api.github.com/users/torvalds/repos").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "name": "linux",
                    "language": "C",
                    "stargazers_count": 170000,
                    "html_url": "https://github.com/torvalds/linux",
                }
            ],
        )
    )
    findings = await GitHubModule()._run("torvalds")
    assert by_label(findings, "Name") == ["Linus Torvalds"]
    assert by_label(findings, "Website") == ["https://linux.org"]  # normalized to https
    assert any(f.label.startswith("Repo linux") for f in findings)


# ----------------------------------------------------------------- HIBP ---
@respx.mock
async def test_hibp_distinguishes_rate_limit_from_no_breach(monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "test-key")
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/breachedaccount/").mock(
        return_value=httpx.Response(429, headers={"retry-after": "3"})
    )
    findings = await HIBPModule()._run("a@example.com")
    assert "Rate limited" in findings[0].value
    assert "unknown" in findings[0].value.lower()


@respx.mock
async def test_hibp_404_means_no_breach(monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", "test-key")
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/breachedaccount/").mock(
        return_value=httpx.Response(404)
    )
    findings = await HIBPModule()._run("a@example.com")
    assert "No breaches found" in findings[0].value


async def test_hibp_is_unavailable_without_a_key(monkeypatch):
    monkeypatch.setattr(settings, "hibp_api_key", None)
    assert HIBPModule().is_available() is False


# -------------------------------------------------------------- Wayback ---
@respx.mock
async def test_wayback_reports_first_and_last_snapshot():
    respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(
            200, json=[["timestamp", "original", "statuscode"], ["20050102030405", "ejemplo.com", "200"]]
        )
    )
    findings = await WaybackModule()._run("ejemplo.com")
    assert by_label(findings, "First snapshot") == ["2005-01-02"]
    assert by_label(findings, "Archived") == ["Yes (Internet Archive)"]


@respx.mock
async def test_wayback_unreachable_archive_returns_nothing():
    respx.get(url__startswith="https://web.archive.org/cdx/search/cdx").mock(
        side_effect=httpx.ConnectError("down")
    )
    assert await WaybackModule()._run("ejemplo.com") == []


# ----------------------------------------------------------------- RDAP ---
@respx.mock
async def test_rdap_parses_structured_registry_data():
    respx.get(url__startswith="https://rdap.org/domain/").mock(
        return_value=httpx.Response(
            200,
            json={
                "handle": "2336799_DOMAIN_COM-VRSN",
                "ldhName": "EJEMPLO.COM",
                "status": ["client transfer prohibited"],
                "events": [
                    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
                ],
                "nameservers": [{"ldhName": "NS1.EJEMPLO.COM."}],
                "secureDNS": {"delegationSigned": True},
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar, Inc."]]],
                        "publicIds": [{"identifier": "292"}],
                        "entities": [
                            {
                                "roles": ["abuse"],
                                "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"]]],
                            }
                        ],
                    }
                ],
            },
        )
    )
    findings = await RDAPModule()._run("ejemplo.com")
    assert by_label(findings, "Registered on") == ["1995-08-14"]
    assert by_label(findings, "Expires on") == ["2027-08-13"]
    assert by_label(findings, "Registrar") == ["Example Registrar, Inc."]
    assert by_label(findings, "Nameserver") == ["ns1.ejemplo.com"]
    assert by_label(findings, "Abuse contact") == ["abuse@registrar.example"]
    assert by_label(findings, "DNSSEC (RDAP)") == ["Signed delegation"]
    assert any("Transfer lock" in v for v in by_label(findings, "Status (RDAP)"))


@respx.mock
async def test_rdap_404_means_not_registered():
    respx.get(url__startswith="https://rdap.org/domain/").mock(return_value=httpx.Response(404))
    findings = await RDAPModule()._run("definitely-not-registered.example")
    assert "Not registered" in findings[0].value


@pytest.mark.parametrize("status", [500, 503])
@respx.mock
async def test_rdap_server_errors_are_silent(status):
    respx.get(url__startswith="https://rdap.org/domain/").mock(return_value=httpx.Response(status))
    assert await RDAPModule()._run("ejemplo.com") == []
