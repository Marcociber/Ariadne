"""
DNS module: queries A, AAAA, MX, NS, TXT, SOA, CAA records for a domain,
detects DMARC policy, tags SPF and resolves inverse DNS (PTR) for IPs.
100% free, no API key required. Uses dnspython.

All data comes from authoritative DNS responses: a record exists or not.
No heuristics that could create false positives.
"""
import asyncio

import dns.asyncresolver
import dns.resolver
import dns.reversename
import dns.exception

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType

_DNS_ERRORS = (
    dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
    dns.resolver.NoNameservers, dns.exception.Timeout,
    dns.resolver.LifetimeTimeout,
)


@register
class DNSModule(OSINTModule):
    name = "dns"
    supported_types = [TargetType.DOMAIN]

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]

    def _resolver(self) -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver()
        r.lifetime = 5.0
        return r

    async def _query_record(self, domain: str, rtype: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            answers = await self._resolver().resolve(domain, rtype)
            for rdata in answers:
                val = str(rdata).strip('"')
                label, cat = f"Record {rtype}", "dns"
                # Tag SPF inside TXT (anti-spoofing policy).
                if rtype == "TXT" and val.lower().startswith("v=spf1"):
                    label, cat = "SPF", "email_security"
                findings.append(Finding(label=label, value=val, category=cat))
        except _DNS_ERRORS:
            pass
        return findings

    async def _query_dmarc(self, domain: str) -> list[Finding]:
        """DMARC policy lives in _dmarc.<domain> as a TXT record."""
        try:
            answers = await self._resolver().resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                val = str(rdata).strip('"')
                if val.lower().startswith("v=dmarc1"):
                    return [Finding(label="DMARC", value=val, category="email_security")]
        except _DNS_ERRORS:
            pass
        return []

    async def _reverse_dns(self, domain: str) -> list[Finding]:
        """Reverse DNS (PTR) for A/AAAA IPs — extra authoritative data."""
        findings: list[Finding] = []
        ips: list[str] = []
        for rt in ("A", "AAAA"):
            try:
                answers = await self._resolver().resolve(domain, rt)
                ips += [str(r) for r in answers]
            except _DNS_ERRORS:
                pass
        for ip in ips:
            try:
                rev = dns.reversename.from_address(ip)
                answers = await self._resolver().resolve(rev, "PTR")
                for r in answers:
                    findings.append(Finding(
                        label=f"Reverse DNS ({ip})",
                        value=str(r).rstrip("."), category="dns"))
            except _DNS_ERRORS:
                pass
        return findings

    async def _run(self, target: str) -> list[Finding]:
        tasks = [self._query_record(target, rt) for rt in self.RECORD_TYPES]
        tasks.append(self._query_dmarc(target))
        tasks.append(self._reverse_dns(target))
        results = await asyncio.gather(*tasks)
        return [f for sub in results for f in sub]
