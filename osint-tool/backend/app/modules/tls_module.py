"""
TLS certificate module (free, no API key required).

Reads the certificate the domain is serving RIGHT NOW: issuer, subject,
validity window, days left, SAN list and the negotiated protocol/cipher.

This complements crt.sh, which reports every certificate ever LOGGED for the
domain: Certificate Transparency tells you what was issued, this tells you
what is actually deployed today.

Uses only the standard library's `ssl` module. The handshake is blocking, so
it runs in a worker thread, and the host is validated against the same SSRF
guard as the HTTP module before any connection is made.
"""

import asyncio
import socket
import ssl
from datetime import UTC, datetime

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType
from ..core.net import UnsafeTargetError, resolve_public_ips

_CONNECT_TIMEOUT = 8.0


def _flatten(pairs) -> dict[str, str]:
    """Turn ssl's nested ((('commonName', 'x'),),) structure into a dict."""
    out: dict[str, str] = {}
    for rdn in pairs or ():
        for key, value in rdn:
            out.setdefault(str(key), str(value))
    return out


def _parse_date(value: str) -> datetime | None:
    """`Jun  1 12:00:00 2026 GMT` -> aware datetime."""
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def _handshake(host: str, port: int = 443) -> dict:
    """Blocking TLS handshake. Returns the certificate and connection facts."""
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            return {
                "cert": tls.getpeercert(),
                "version": tls.version(),
                "cipher": tls.cipher(),
                "verified": True,
            }
    except ssl.SSLCertVerificationError as exc:
        # A certificate that does not validate is itself a finding.
        return {"cert": None, "verified": False, "error": exc.verify_message or str(exc)}


@register
class TLSModule(OSINTModule):
    name = "tls"
    supported_types = [TargetType.DOMAIN]

    async def _run(self, target: str) -> list[Finding]:
        try:
            await resolve_public_ips(target)
        except UnsafeTargetError as exc:
            return [
                Finding(
                    label="TLS certificate",
                    value=f"Refused: {exc}",
                    category="tls",
                    confidence=0.9,
                )
            ]

        try:
            info = await asyncio.to_thread(_handshake, target)
        except (OSError, ssl.SSLError) as exc:
            return [
                Finding(
                    label="TLS certificate",
                    value=f"No TLS service on port 443 ({type(exc).__name__})",
                    category="tls",
                    confidence=0.9,
                )
            ]

        if not info.get("verified"):
            return [
                Finding(
                    label="TLS certificate",
                    value=f"Served but INVALID: {info.get('error', 'verification failed')}",
                    category="tls",
                    confidence=0.95,
                )
            ]

        cert = info.get("cert") or {}
        findings: list[Finding] = [
            Finding(
                label="TLS certificate",
                value="Valid for this hostname",
                category="tls",
                confidence=0.95,
            )
        ]

        if info.get("version"):
            findings.append(Finding(label="TLS version", value=info["version"], category="tls"))
        cipher = info.get("cipher")
        if cipher:
            findings.append(
                Finding(label="Cipher suite", value=f"{cipher[0]} ({cipher[2]} bits)", category="tls")
            )

        issuer = _flatten(cert.get("issuer"))
        subject = _flatten(cert.get("subject"))
        if issuer.get("organizationName"):
            findings.append(
                Finding(label="Certificate issuer", value=issuer["organizationName"], category="cert")
            )
        if issuer.get("commonName"):
            findings.append(
                Finding(
                    label="Issuer CN",
                    value=issuer["commonName"],
                    category="cert",
                    confidence=0.9,
                )
            )
        if subject.get("commonName"):
            findings.append(
                Finding(label="Certificate subject (CN)", value=subject["commonName"], category="cert")
            )
        if subject.get("organizationName"):
            findings.append(
                Finding(
                    label="Certificate organization",
                    value=subject["organizationName"],
                    category="cert",
                    confidence=0.95,
                )
            )

        not_before = _parse_date(cert.get("notBefore", ""))
        not_after = _parse_date(cert.get("notAfter", ""))
        if not_before:
            findings.append(
                Finding(label="Certificate issued", value=not_before.date().isoformat(), category="cert")
            )
        if not_after:
            findings.append(
                Finding(label="Certificate expires", value=not_after.date().isoformat(), category="cert")
            )
            days = (not_after - datetime.now(UTC)).days
            findings.append(
                Finding(
                    label="Days until certificate expiry",
                    value=str(days) if days >= 0 else f"EXPIRED ({abs(days)} days ago)",
                    category="cert",
                    confidence=0.95,
                )
            )
        if cert.get("serialNumber"):
            findings.append(
                Finding(
                    label="Certificate serial",
                    value=str(cert["serialNumber"]),
                    category="cert",
                    confidence=0.9,
                )
            )

        # Subject Alternative Names: every other host this certificate covers.
        sans = sorted({v.lower() for kind, v in cert.get("subjectAltName", ()) if kind == "DNS"})
        if sans:
            findings.append(
                Finding(
                    label="Hostnames on certificate",
                    value=str(len(sans)),
                    category="cert",
                    confidence=0.95,
                )
            )
        findings += [
            Finding(label="Certificate SAN", value=san, category="subdomain", confidence=0.95)
            for san in sans[:50]
        ]
        return findings
