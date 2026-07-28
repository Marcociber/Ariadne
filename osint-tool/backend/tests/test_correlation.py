"""
Correlation engine: also a pure function over data structures.
"""

from app.core.correlation import correlate
from app.core.models import CorrelationKind, Finding, ModuleResult, ModuleStatus, TargetType


def result(module: str, *findings: Finding) -> ModuleResult:
    return ModuleResult(
        module=module,
        target="example.com",
        target_type=TargetType.DOMAIN,
        status=ModuleStatus.OK,
        findings=list(findings),
    )


def test_value_seen_by_two_modules_correlates():
    results = [
        result("dns", Finding(label="Record A", value="93.184.216.34", category="dns")),
        result("shodan", Finding(label="Resolved IP", value="93.184.216.34", category="shodan")),
    ]
    correlations = correlate(results)
    assert len(correlations) == 1
    assert correlations[0].kind is CorrelationKind.IP
    assert correlations[0].modules == ["dns", "shodan"]


def test_a_single_module_never_correlates_with_itself():
    results = [
        result(
            "dns",
            Finding(label="Record A", value="93.184.216.34", category="dns"),
            Finding(label="Record A", value="93.184.216.34", category="dns"),
        )
    ]
    assert correlate(results) == []


def test_normalization_matches_dns_and_whois_spellings():
    """`NS1.EXAMPLE.COM.` and `ns1.example.com` are the same nameserver."""
    results = [
        result("dns", Finding(label="Record NS", value="ns1.example.com.", category="dns")),
        result("whois", Finding(label="Nameserver", value="NS1.EXAMPLE.COM", category="whois")),
    ]
    correlations = correlate(results)
    assert len(correlations) == 1
    assert correlations[0].kind is CorrelationKind.NAMESERVER


def test_www_prefix_is_folded():
    results = [
        result("dns", Finding(label="www (A)", value="www.example.com", category="dns")),
        result("crtsh", Finding(label="Subdomain", value="example.com", category="subdomain")),
    ]
    assert len(correlate(results)) == 1


def test_ipv6_spelling_is_canonicalized():
    results = [
        result("dns", Finding(label="Record AAAA", value="2001:0db8:0000::1", category="dns")),
        result("ip", Finding(label="Address", value="2001:db8::1", category="ip")),
    ]
    correlations = correlate(results)
    assert len(correlations) == 1
    assert correlations[0].kind is CorrelationKind.IP


def test_pivot_category_is_excluded():
    """Pivot values are URLs the tool builds itself, not observed data."""
    url = "https://www.google.com/search?q=example"
    results = [
        result("email", Finding(label="Web search", value=url, category="pivot")),
        result("ip", Finding(label="Web search", value=url, category="pivot")),
    ]
    assert correlate(results) == []


def test_status_sentences_are_not_correlated():
    msg = "Refused: 10.0.0.1 is not a globally routable address"
    results = [
        result("http", Finding(label="Website not fetched", value=msg, category="web_security")),
        result("tls", Finding(label="TLS certificate", value=msg, category="tls")),
    ]
    assert correlate(results) == []


def test_short_values_are_ignored():
    results = [
        result("dns", Finding(label="A", value="yes", category="dns")),
        result("http", Finding(label="B", value="yes", category="web")),
    ]
    assert correlate(results) == []


def test_punctuation_variants_of_an_organization_are_one_entity():
    """`Cloudflare, Inc.` and `Cloudflare Inc` normalize to the same key."""
    results = [
        result("whois", Finding(label="Organization", value="Cloudflare, Inc.", category="whois")),
        result("ip", Finding(label="Organization", value="Cloudflare Inc", category="network")),
    ]
    correlations = correlate(results)
    assert len(correlations) == 1
    assert correlations[0].kind is CorrelationKind.ORGANIZATION


def test_fuzzy_matching_links_near_identical_organizations():
    """Different keys, same entity: caught by fuzzy matching, not equality."""
    results = [
        result(
            "whois", Finding(label="Organization", value="Amazon Data Services Ireland", category="whois")
        ),
        result(
            "ip", Finding(label="Organization", value="Amazon Data Services Ireland Ltd", category="network")
        ),
    ]
    kinds = {c.kind for c in correlate(results)}
    assert CorrelationKind.SIMILAR in kinds


def test_fuzzy_matching_does_not_link_unrelated_organizations():
    results = [
        result("whois", Finding(label="Organization", value="Cloudflare, Inc.", category="whois")),
        result("ip", Finding(label="Organization", value="Hetzner Online GmbH", category="network")),
    ]
    assert correlate(results) == []


def test_correlations_are_sorted_by_weight():
    results = [
        result(
            "dns",
            Finding(label="Record A", value="93.184.216.34", category="dns"),
            Finding(label="Generator", value="SomeGenerator9000", category="tech"),
        ),
        result(
            "http",
            Finding(label="Resolved IP", value="93.184.216.34", category="web"),
            Finding(label="Generator (meta)", value="SomeGenerator9000", category="tech"),
        ),
    ]
    correlations = correlate(results)
    assert len(correlations) == 2
    assert correlations[0].weight >= correlations[1].weight
    assert correlations[0].kind is CorrelationKind.IP
