"""
Target detection: a pure function with no external dependencies, which makes
it the cheapest and most valuable test in the project.
"""

import pytest

from app.core.detector import Detection, analyze, detect_type, normalize_target
from app.core.models import TargetType


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ann@example.com", TargetType.EMAIL),
        ("Ann.Smith+tag@Example.COM", TargetType.EMAIL),
        ("example.com", TargetType.DOMAIN),
        ("sub.example.co.uk", TargetType.DOMAIN),
        ("8.8.8.8", TargetType.IP),
        ("2001:4860:4860::8888", TargetType.IP),
        ("192.168.1.1", TargetType.IP),
        ("+34600123456", TargetType.PHONE),
        ("+1 (555) 123-4567", TargetType.PHONE),
        ("torvalds", TargetType.USERNAME),
        ("some_user-1.2", TargetType.USERNAME),
    ],
)
def test_detects_each_type(raw, expected):
    assert detect_type(raw) is expected


def test_ip_wins_over_phone():
    """8.8.8.8 is mostly digits; it must never read as a phone number."""
    assert detect_type("8.8.8.8") is TargetType.IP


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://example.com/path?q=1", "example.com"),
        ("http://Example.COM", "example.com"),
        ("example.com/some/page", "example.com"),
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
        ("<example.com>", "example.com"),
        ("mailto:Ann@Example.com", "ann@example.com"),
        ("https://user:pw@example.com:8443/x", "example.com"),
    ],
)
def test_normalizes_common_input_shapes(raw, expected):
    """A pasted URL used to fall through to UNKNOWN."""
    assert normalize_target(raw) == expected


def test_full_url_is_detected_as_domain():
    result = analyze("https://example.com/a/b?c=d")
    assert result == Detection("example.com", TargetType.DOMAIN, None)


def test_internationalized_domain_becomes_punycode():
    assert normalize_target("bücher.de") == "xn--bcher-kva.de"
    assert detect_type("bücher.de") is TargetType.DOMAIN


def test_single_host_cidr_is_an_ip():
    result = analyze("8.8.8.8/32")
    assert result.type is TargetType.IP
    assert result.target == "8.8.8.8"


def test_network_range_is_rejected_with_a_reason():
    result = analyze("10.0.0.0/24")
    assert result.type is TargetType.UNKNOWN
    assert "range" in (result.reason or "").lower()


def test_unknown_always_explains_itself():
    """An empty result with no explanation was the previous behaviour."""
    result = analyze("!!! not a target !!!")
    assert result.type is TargetType.UNKNOWN
    assert result.reason


def test_empty_input():
    result = analyze("   ")
    assert result.type is TargetType.UNKNOWN
    assert result.reason
