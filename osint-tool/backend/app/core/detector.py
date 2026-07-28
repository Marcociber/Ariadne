"""
Automatically detect which target type the user entered.

The input is normalized first, so the common shapes people actually paste all
work: a full URL, a `mailto:` link, a hostname with a trailing dot, an
internationalized domain (converted to punycode) or a single-host CIDR.

When nothing matches, the reason is reported instead of silently returning
UNKNOWN and leaving the user with an empty result and no explanation.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import TargetType

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Domain: something.tld (no @, no spaces, at least one dot).
# Labels follow the LDH rule and may contain consecutive hyphens, which is
# what punycode uses: `bücher.de` becomes `xn--bcher-kva.de`.
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
# Phone: optional +, digits, spaces, dashes and parentheses
PHONE_RE = re.compile(r"^\+?[\d\s\-()]{7,}$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,40}$")

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


@dataclass(frozen=True)
class Detection:
    """Result of analyzing raw user input."""

    target: str  # normalized target to actually scan
    type: TargetType
    reason: str | None = None  # populated only when type is UNKNOWN


def _to_punycode(host: str) -> str:
    """Convert an internationalized hostname to its ASCII (punycode) form."""
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return host


def _is_ip(target: str) -> bool:
    """True for a valid IPv4 or IPv6 address (public or private)."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def normalize_target(raw: str) -> str:
    """Reduce user input to the bare target a module can work with.

    `https://Example.com/path?q=1` -> `example.com`
    `mailto:Ann@Example.COM`       -> `ann@example.com`
    `example.com.`                 -> `example.com`
    `ejemplo-ñ.es`                 -> `xn--ejemplo--1za.es`
    """
    t = raw.strip().strip("<>").strip("\"'").strip()
    if not t:
        return ""

    if t.lower().startswith("mailto:"):
        t = t[7:].split("?", 1)[0].strip()

    # A CIDR block must survive intact: `10.0.0.0/24` is not a URL whose host
    # is `10.0.0.0`, and stripping the prefix would silently change the target.
    if "/" in t and not _SCHEME_RE.match(t):
        try:
            ipaddress.ip_network(t, strict=False)
        except ValueError:
            pass
        else:
            return t.lower()

    # A URL (with or without an explicit scheme): keep the host only.
    if _SCHEME_RE.match(t) or ("/" in t and "@" not in t):
        candidate = t if _SCHEME_RE.match(t) else f"//{t}"
        host = urlsplit(candidate).hostname or ""
        if host:
            t = host

    t = t.strip().rstrip(".")

    # Lower-case and punycode the domain part (never the local part of an
    # email, which is technically case-sensitive but conventionally folded).
    if "@" in t:
        local, _, domain = t.rpartition("@")
        return f"{local.lower()}@{_to_punycode(domain.lower())}"
    if _is_ip(t):
        return t.lower()
    return _to_punycode(t.lower()) if not t.startswith("+") else t


def analyze(raw: str) -> Detection:
    """Normalize the input and classify it, explaining any failure."""
    t = normalize_target(raw)
    if not t:
        return Detection(t, TargetType.UNKNOWN, "The target is empty.")

    if EMAIL_RE.match(t):
        return Detection(t, TargetType.EMAIL)

    # IP address (checked before phone/domain: 8.8.8.8 must not read as a phone).
    if _is_ip(t):
        return Detection(t, TargetType.IP)

    # A CIDR block: usable only when it describes a single host.
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            pass
        else:
            if net.num_addresses == 1:
                return Detection(str(net.network_address), TargetType.IP)
            return Detection(
                t,
                TargetType.UNKNOWN,
                f"{t} is a network range ({net.num_addresses} addresses). "
                "Scan a single IP address instead.",
            )

    # A phone number: mostly digits and phone characters
    digits = sum(c.isdigit() for c in t)
    if PHONE_RE.match(t) and digits >= 7:
        return Detection(t, TargetType.PHONE)

    if DOMAIN_RE.match(t):
        return Detection(t, TargetType.DOMAIN)

    # Username: alphanumeric + . _ - without dots forming a domain
    if USERNAME_RE.match(t):
        return Detection(t, TargetType.USERNAME)

    if "@" in t:
        reason = f"'{t}' looks like an email address but is not a valid one."
    elif "." in t:
        reason = f"'{t}' looks like a domain but does not have a valid public suffix."
    elif digits and digits >= len(t) - 3:
        reason = f"'{t}' looks like a phone number but is too short (needs at least 7 digits)."
    else:
        reason = (
            f"Could not recognize '{t}' as a domain, email, username, phone number or IP. "
            "Pick the type manually if you know what it is."
        )
    return Detection(t, TargetType.UNKNOWN, reason)


def detect_type(target: str) -> TargetType:
    """Classify a target. Thin wrapper over `analyze` for callers that only
    need the type."""
    return analyze(target).type
