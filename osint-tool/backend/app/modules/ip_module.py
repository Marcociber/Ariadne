"""
IP module (free, no API key required):
    - Geolocation, ISP, organization and ASN via ip-api.com (free tier,
      no key, HTTP endpoint). Also flags mobile / proxy / hosting IPs.
    - Reverse DNS (PTR) via dnspython.
    - Classification for private / reserved / loopback ranges (offline).
    - OSINT pivot links (Shodan, Censys, VirusTotal, AbuseIPDB, GreyNoise),
      only constructed — never queried.

Everything comes from an authoritative response (ip-api's JSON, a real PTR
record) or deterministic analysis of the address itself. No guesswork.
"""
import ipaddress
from urllib.parse import quote

import dns.asyncresolver
import dns.resolver
import dns.reversename
import dns.exception
import httpx

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType

_DNS_ERRORS = (
    dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
    dns.resolver.NoNameservers, dns.exception.Timeout,
    dns.resolver.LifetimeTimeout,
)

# Fields we ask ip-api for (some, like reverse/mobile/proxy, are opt-in).
_IPAPI_FIELDS = (
    "status,message,continent,country,countryCode,region,regionName,city,"
    "zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)


@register
class IPModule(OSINTModule):
    name = "ip"
    supported_types = [TargetType.IP]

    def _resolver(self) -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver()
        r.lifetime = 5.0
        return r

    def _classify(self, ip: str) -> list[Finding]:
        """Offline classification of the address (version, scope)."""
        findings: list[Finding] = []
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return findings
        findings.append(Finding(label="IP version", value=f"IPv{obj.version}", category="ip"))
        scope = None
        if obj.is_loopback:
            scope = "Loopback (localhost)"
        elif obj.is_private:
            scope = "Private (RFC 1918 / non-routable)"
        elif obj.is_link_local:
            scope = "Link-local"
        elif obj.is_reserved:
            scope = "Reserved"
        elif obj.is_multicast:
            scope = "Multicast"
        else:
            scope = "Public (globally routable)"
        findings.append(Finding(label="Address scope", value=scope, category="ip"))
        return findings

    async def _geolocate(self, ip: str) -> list[Finding]:
        """ip-api.com free endpoint: geo + network ownership. No key required."""
        url = f"http://ip-api.com/json/{quote(ip)}?fields={_IPAPI_FIELDS}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers={"User-Agent": "osint-tool"})
            data = resp.json()
        except (httpx.HTTPError, ValueError):
            return []
        if data.get("status") != "success":
            return []

        findings: list[Finding] = []

        def add(label, key, category="geo", conf=1.0):
            v = data.get(key)
            if v not in (None, "", 0):
                findings.append(Finding(label=label, value=str(v), category=category, confidence=conf))

        # --- Geolocation (IP geo is approximate: medium confidence) ---
        country = data.get("country")
        cc = data.get("countryCode")
        if country:
            findings.append(Finding(
                label="Country", value=f"{country}" + (f" ({cc})" if cc else ""),
                category="geo", confidence=0.8))
        add("Region", "regionName", conf=0.7)
        add("City", "city", conf=0.6)
        add("Postal code", "zip", conf=0.6)
        add("Timezone", "timezone")
        lat, lon = data.get("lat"), data.get("lon")
        if lat is not None and lon is not None:
            findings.append(Finding(label="Coordinates", value=f"{lat}, {lon}", category="geo", confidence=0.6))
            findings.append(Finding(
                label="Map", value=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}",
                category="pivot", confidence=0.6))

        # --- Network ownership (authoritative from RIR data) ---
        add("ISP", "isp", category="network")
        add("Organization", "org", category="network")
        add("ASN", "as", category="network")
        add("AS name", "asname", category="network")

        # --- Threat / usage signals ---
        if data.get("reverse"):
            findings.append(Finding(label="Reverse DNS (ip-api)", value=data["reverse"], category="ip"))
        for label, key in (("Mobile network", "mobile"), ("Proxy / VPN / Tor", "proxy"), ("Hosting / datacenter", "hosting")):
            if data.get(key) is True:
                findings.append(Finding(label=label, value="Yes", category="reputation", confidence=0.8))
        return findings

    async def _reverse_dns(self, ip: str) -> list[Finding]:
        try:
            rev = dns.reversename.from_address(ip)
            answers = await self._resolver().resolve(rev, "PTR")
            return [Finding(label="Reverse DNS (PTR)", value=str(r).rstrip("."), category="ip")
                    for r in answers]
        except (_DNS_ERRORS + (dns.exception.SyntaxError,)):
            return []

    def _pivots(self, ip: str) -> list[Finding]:
        q = quote(ip)
        links = [
            ("Shodan", f"https://www.shodan.io/host/{q}"),
            ("Censys", f"https://search.censys.io/hosts/{q}"),
            ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{q}"),
            ("AbuseIPDB", f"https://www.abuseipdb.com/check/{q}"),
            ("GreyNoise", f"https://viz.greynoise.io/ip/{q}"),
            ("Web search", f"https://www.google.com/search?q={quote(chr(34) + ip + chr(34))}"),
        ]
        return [Finding(label=f"Look up on {name}", value=url, category="pivot", confidence=0.5)
                for name, url in links]

    async def _run(self, target: str) -> list[Finding]:
        ip = target.strip()
        findings: list[Finding] = []
        findings += self._classify(ip)

        # Only query the geo API for globally routable addresses.
        try:
            is_global = ipaddress.ip_address(ip).is_global
        except ValueError:
            is_global = False
        if is_global:
            findings += await self._geolocate(ip)
        findings += await self._reverse_dns(ip)
        findings += self._pivots(ip)
        return findings
