"""
SSRF guard — the highest-severity finding in the audit.

`POST /scan` accepts an arbitrary target AND lets the caller force the type,
so `{"target": "169.254.169.254", "target_type": "domain"}` made the backend
fetch the cloud metadata endpoint.
"""

import pytest

from app.core.net import UnsafeTargetError, assert_safe_url, resolve_public_ips
from app.modules.http_module import HTTPModule
from app.modules.tls_module import TLSModule


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",  # loopback
        "10.0.0.1",  # RFC 1918
        "192.168.1.1",  # RFC 1918
        "172.16.0.1",  # RFC 1918
        "169.254.169.254",  # cloud metadata endpoint
        "0.0.0.0",  # unspecified
        "::1",  # IPv6 loopback
        "fd00::1",  # IPv6 unique-local
        "localhost",
    ],
)
async def test_private_and_reserved_addresses_are_refused(target):
    with pytest.raises(UnsafeTargetError):
        await resolve_public_ips(target)


async def test_public_address_is_allowed():
    assert await resolve_public_ips("8.8.8.8") == ["8.8.8.8"]


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:11211/",
        "ftp://192.168.0.1/",
    ],
)
async def test_non_http_schemes_are_refused(url):
    with pytest.raises(UnsafeTargetError):
        await assert_safe_url(url)


async def test_http_module_reports_the_refusal_instead_of_fetching():
    findings = await HTTPModule()._run("169.254.169.254")
    assert len(findings) == 1
    assert findings[0].value.startswith("Refused:")
    assert "globally routable" in findings[0].value


async def test_tls_module_refuses_internal_hosts_too():
    findings = await TLSModule()._run("127.0.0.1")
    assert findings[0].value.startswith("Refused:")
