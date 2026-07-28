"""
Public Suffix List helpers — these back the crt.sh false-positive fix.
"""

from app.core.domains import is_hostname, is_subdomain_of, registrable_domain


def test_label_boundary_is_respected():
    """The bug this replaces: `sub.endswith(target)` accepted this."""
    assert is_subdomain_of("mail.ejemplo.com", "ejemplo.com") is True
    assert is_subdomain_of("noesejemplo.com", "ejemplo.com") is False
    assert is_subdomain_of("xejemplo.com", "ejemplo.com") is False


def test_a_domain_is_not_its_own_subdomain():
    assert is_subdomain_of("ejemplo.com", "ejemplo.com") is False


def test_case_and_trailing_dot_do_not_matter():
    assert is_subdomain_of("MAIL.Ejemplo.com.", "ejemplo.com") is True


def test_registrable_domain_uses_the_public_suffix_list():
    assert registrable_domain("www.blog.example.co.uk") == "example.co.uk"
    assert registrable_domain("a.b.c.example.com") == "example.com"


def test_is_hostname():
    assert is_hostname("example.com") is True
    assert is_hostname("ns1.example.com") is True
    assert is_hostname("not a host") is False
    assert is_hostname("example.invalidtldthatdoesnotexist") is False
    assert is_hostname("") is False
