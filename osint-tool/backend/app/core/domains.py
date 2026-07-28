"""
Domain-name helpers backed by the Public Suffix List (tldextract).

Naive suffix checks are what made crt.sh report `noesejemplo.com` as a
subdomain of `ejemplo.com` (`sub.endswith(target)`), which contradicts the
project's "no false positives" promise. Everything that needs to reason about
"is X under Y" goes through here instead.

The extractor is built with `suffix_list_urls=()` so it uses the snapshot
bundled with tldextract: no network call at import time, and tests stay
offline and deterministic.
"""

from __future__ import annotations

import re

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_](-?[a-zA-Z0-9_])*\.)+[a-zA-Z]{2,}$")


def clean_host(value: str) -> str:
    """Lower-case a hostname and drop the trailing root dot."""
    return value.strip().strip(".").lower()


def is_hostname(value: str) -> bool:
    """True when the value is a syntactically valid host with a real suffix."""
    host = clean_host(value)
    if not host or " " in host or _HOSTNAME_RE.match(host) is None:
        return False
    return bool(_extract(host).suffix)


def registrable_domain(value: str) -> str:
    """`www.blog.example.co.uk` -> `example.co.uk` (empty if not a host)."""
    parts = _extract(clean_host(value))
    return parts.registered_domain if parts.suffix else ""


def is_subdomain_of(candidate: str, parent: str) -> bool:
    """True when `candidate` is strictly below `parent` in the DNS tree.

    Unlike `endswith`, `noesejemplo.com` is NOT a subdomain of `ejemplo.com`,
    because the label boundary is checked.
    """
    c, p = clean_host(candidate), clean_host(parent)
    if not c or not p or c == p:
        return False
    return c.endswith("." + p)
