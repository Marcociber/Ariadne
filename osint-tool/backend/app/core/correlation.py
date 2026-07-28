"""
Correlation engine — the "thread of Ariadne" that ties sources together.

The first version compared raw strings for exact equality and emitted one
generic description for every match. This version:

  * NORMALIZES before comparing (case, trailing DNS dot, `www.` prefix,
    IPv6 spelling) so `NS1.EXAMPLE.COM.` and `ns1.example.com` are one value;
  * TYPES each correlation (same IP, same nameserver, same mail host, same
    email, same host, same organization) and gives it a weight, because a
    shared IP is a far stronger signal than a shared word;
  * IGNORES the `pivot` category, whose values are URLs the tool constructed
    itself rather than observed data — they used to dominate the graph;
  * adds FUZZY matching for organization-like values, so `Cloudflare, Inc.`
    and `Cloudflare Inc` are recognized as the same entity.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from rapidfuzz import fuzz

from .domains import clean_host, is_hostname
from .models import Correlation, CorrelationKind, ModuleResult

# Values from these categories are constructed by the tool, not observed, so
# correlating them only produces noise.
EXCLUDED_CATEGORIES = {"pivot"}

MIN_VALUE_LENGTH = 4

# How much each kind of link is worth (0.0 - 1.0).
KIND_WEIGHTS: dict[CorrelationKind, float] = {
    CorrelationKind.IP: 0.95,
    CorrelationKind.NAMESERVER: 0.9,
    CorrelationKind.MAIL_HOST: 0.9,
    CorrelationKind.EMAIL: 0.9,
    CorrelationKind.HOSTNAME: 0.8,
    CorrelationKind.ORGANIZATION: 0.7,
    CorrelationKind.VALUE: 0.5,
    CorrelationKind.SIMILAR: 0.4,
}

KIND_DESCRIPTIONS: dict[CorrelationKind, str] = {
    CorrelationKind.IP: "Same IP address seen by several sources",
    CorrelationKind.NAMESERVER: "Same nameserver",
    CorrelationKind.MAIL_HOST: "Same mail host",
    CorrelationKind.EMAIL: "Same email address",
    CorrelationKind.HOSTNAME: "Same host",
    CorrelationKind.ORGANIZATION: "Same organization",
    CorrelationKind.VALUE: "Value referenced by multiple sources",
    CorrelationKind.SIMILAR: "Near-identical values (likely the same entity)",
}

# Labels whose values name infrastructure, matched case-insensitively.
_NAMESERVER_HINTS = ("nameserver", "name server", "record ns")
_MAIL_HINTS = ("mx server", "mx record", "mail host", "record mx")
_ORG_LABELS = ("organization", "org", "isp", "company", "registrar", "registrant")

# Organization-like values shorter than this are not fuzzy-matched: short
# strings produce accidental similarities.
_FUZZY_MIN_LENGTH = 6
_FUZZY_THRESHOLD = 92.0


@dataclass
class _Bucket:
    """Every module that reported one normalized value, plus its spellings."""

    kind: CorrelationKind
    modules: set[str] = field(default_factory=set)
    spellings: list[str] = field(default_factory=list)

    def add(self, module: str, spelling: str, kind: CorrelationKind) -> None:
        self.modules.add(module)
        if spelling not in self.spellings:
            self.spellings.append(spelling)
        # Keep the most specific kind seen for this value.
        if KIND_WEIGHTS[kind] > KIND_WEIGHTS[self.kind]:
            self.kind = kind


def _as_ip(value: str) -> str | None:
    """Return the canonical form of an IP literal, or None."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _classify(label: str, category: str, value: str) -> CorrelationKind:
    low_label = label.lower()
    if _as_ip(value):
        return CorrelationKind.IP
    if any(h in low_label for h in _NAMESERVER_HINTS):
        return CorrelationKind.NAMESERVER
    if any(h in low_label for h in _MAIL_HINTS):
        return CorrelationKind.MAIL_HOST
    if "@" in value and " " not in value.strip():
        return CorrelationKind.EMAIL
    if any(low_label == lbl or low_label.startswith(lbl + " ") for lbl in _ORG_LABELS):
        return CorrelationKind.ORGANIZATION
    if is_hostname(value):
        return CorrelationKind.HOSTNAME
    if category in ("network", "whois") and len(value) >= _FUZZY_MIN_LENGTH:
        return CorrelationKind.ORGANIZATION
    return CorrelationKind.VALUE


def _is_prose(value: str) -> bool:
    """True for status text rather than an entity.

    Modules report human sentences too ("Refused: 10.0.0.1 is not a globally
    routable address", "Enabled (enforced TLS policy)"). Three modules
    printing the same sentence is not a correlation, it is noise.
    """
    return ": " in value or len(value.split()) > 6


def _normalize(value: str, kind: CorrelationKind) -> str | None:
    """Canonical comparison key for a value, or None when not comparable."""
    v = value.strip()
    if len(v) < MIN_VALUE_LENGTH:
        return None
    if kind in (CorrelationKind.VALUE, CorrelationKind.ORGANIZATION) and _is_prose(v):
        return None

    if kind is CorrelationKind.IP:
        return _as_ip(v)
    if kind in (CorrelationKind.HOSTNAME, CorrelationKind.NAMESERVER, CorrelationKind.MAIL_HOST):
        host = clean_host(v)
        # `www.` is a conventional alias of the bare host; treat them as one.
        return host[4:] if host.startswith("www.") else host
    if kind is CorrelationKind.EMAIL:
        return v.lower()
    if kind is CorrelationKind.ORGANIZATION:
        # Drop punctuation and legal suffixes that vary between registries.
        cleaned = v.lower().replace(",", " ").replace(".", " ")
        return " ".join(cleaned.split())
    return v.lower()


def _fuzzy_pairs(buckets: dict[str, _Bucket]) -> list[Correlation]:
    """Link organization-like values that are near-identical but not equal."""
    candidates = [
        (key, bucket)
        for key, bucket in buckets.items()
        if bucket.kind is CorrelationKind.ORGANIZATION and len(key) >= _FUZZY_MIN_LENGTH
    ]
    out: list[Correlation] = []
    for i in range(len(candidates)):
        key_a, bucket_a = candidates[i]
        for j in range(i + 1, len(candidates)):
            key_b, bucket_b = candidates[j]
            # A link is only interesting when it spans at least two sources.
            if len(bucket_a.modules | bucket_b.modules) < 2:
                continue
            if fuzz.token_sort_ratio(key_a, key_b) < _FUZZY_THRESHOLD:
                continue
            out.append(
                Correlation(
                    description=KIND_DESCRIPTIONS[CorrelationKind.SIMILAR],
                    linked_values=[bucket_a.spellings[0], bucket_b.spellings[0]],
                    modules=sorted(bucket_a.modules | bucket_b.modules),
                    kind=CorrelationKind.SIMILAR,
                    weight=KIND_WEIGHTS[CorrelationKind.SIMILAR],
                )
            )
    return out


def correlate(results: list[ModuleResult]) -> list[Correlation]:
    """Cross-reference findings from different modules.

    A correlation is emitted when the same normalized value is reported by two
    or more modules, or when two organization-like values from different
    modules are near-identical.
    """
    buckets: dict[str, _Bucket] = {}

    for res in results:
        seen_in_module: set[str] = set()
        for f in res.findings:
            if f.category in EXCLUDED_CATEGORIES:
                continue
            kind = _classify(f.label, f.category, f.value)
            key = _normalize(f.value, kind)
            if not key or len(key) < MIN_VALUE_LENGTH:
                continue
            # A module repeating a value does not make it a correlation.
            marker = f"{kind.value}:{key}"
            if marker in seen_in_module:
                continue
            seen_in_module.add(marker)

            bucket = buckets.get(key)
            if bucket is None:
                bucket = buckets[key] = _Bucket(kind=kind)
            bucket.add(res.module, f.value.strip(), kind)

    correlations = [
        Correlation(
            description=KIND_DESCRIPTIONS[bucket.kind],
            linked_values=bucket.spellings[:3],
            modules=sorted(bucket.modules),
            kind=bucket.kind,
            weight=KIND_WEIGHTS[bucket.kind],
        )
        for bucket in buckets.values()
        if len(bucket.modules) >= 2
    ]
    correlations += _fuzzy_pairs(buckets)

    # Strongest links first: the UI shows them in this order.
    correlations.sort(key=lambda c: (-c.weight, c.linked_values[0]))
    return correlations


__all__ = ["EXCLUDED_CATEGORIES", "KIND_WEIGHTS", "correlate"]
