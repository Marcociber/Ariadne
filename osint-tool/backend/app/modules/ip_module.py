"""
IP module (free, no API key required):
    - Geolocation by CONSENSUS across several free, key-less providers
      (ip-api.com, ipwho.is, geojs.io, reallyfreegeoip.org). Each field
      (country, region,
      city, coordinates) is a majority vote: agreement raises confidence,
      disagreement is surfaced and the coordinate spread is reported so an
      approximate fix is never presented as exact.
    - Network ownership: ISP, organization and ASN (authoritative RIR data).
    - Reverse DNS (PTR) via dnspython.
    - Classification for private / reserved / loopback ranges (offline).
    - Mobile / proxy / hosting flags and OSINT pivot links (Shodan, Censys,
      VirusTotal, AbuseIPDB, GreyNoise), only constructed — never queried.

Everything comes from real provider responses or deterministic analysis of
the address itself. Confidence reflects cross-source agreement, not a guess.

PRIVACY NOTE: ip-api.com only serves HTTPS on paid plans, so that one query
travels in cleartext and the address being investigated is visible to anyone
on the path. The scan says so explicitly when the source is used, and
ENABLE_INSECURE_IPAPI=false drops it from the consensus entirely.
"""

import asyncio
import ipaddress
import math
from collections import Counter
from urllib.parse import quote

import httpx

from ..core.base import OSINTModule, register
from ..core.config import settings
from ..core.models import Finding, TargetType
from ..core.net import get_client
from ..core.resolver import reverse

# Fields we ask ip-api for (some, like reverse/mobile/proxy, are opt-in).
_IPAPI_FIELDS = (
    "status,message,country,countryCode,regionName,city,"
    "zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
)


def _haversine(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance in km between two (lat, lon) points."""
    r = 6371.0
    p1, p2 = math.radians(a[0]), math.radians(b[0])
    dp = math.radians(b[0] - a[0])
    dl = math.radians(b[1] - a[1])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


def _vote(values: list[str]):
    """Majority vote over non-empty strings. Returns (winner, count, total)."""
    clean = [v.strip() for v in values if v and v.strip()]
    if not clean:
        return None, 0, 0
    # Vote case-insensitively but keep the most common original spelling.
    norm = Counter(v.lower() for v in clean)
    top_key, count = norm.most_common(1)[0]
    winner = next(v for v in clean if v.lower() == top_key)
    return winner, count, len(clean)


def _conf(count: int, total: int, base: float, span: float) -> float:
    """Confidence from cross-source agreement (a single source is discounted)."""
    if total == 0:
        return base
    conf = base + span * (count / total)
    if total == 1:
        conf *= 0.85  # one unverified source
    return round(min(conf, 0.95), 2)


@register
class IPModule(OSINTModule):
    name = "ip"
    supported_types = [TargetType.IP]

    def _classify(self, ip: str) -> list[Finding]:
        """Offline classification of the address (version, scope)."""
        findings: list[Finding] = []
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return findings
        findings.append(Finding(label="IP version", value=f"IPv{obj.version}", category="ip"))
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

    # ---------- geolocation providers (each returns a normalized dict) ----------
    async def _from_ipapi(self, client: httpx.AsyncClient, ip: str) -> dict | None:
        url = f"http://ip-api.com/json/{quote(ip)}?fields={_IPAPI_FIELDS}"
        try:
            d = (await client.get(url)).json()
        except (httpx.HTTPError, ValueError):
            return None
        if d.get("status") != "success":
            return None
        return {
            "source": "ip-api.com",
            "country": d.get("country"),
            "country_code": d.get("countryCode"),
            "region": d.get("regionName"),
            "city": d.get("city"),
            "postal": d.get("zip"),
            "lat": d.get("lat"),
            "lon": d.get("lon"),
            "timezone": d.get("timezone"),
            "isp": d.get("isp"),
            "org": d.get("org"),
            "asn": d.get("as"),
            "reverse": d.get("reverse"),
            "mobile": d.get("mobile"),
            "proxy": d.get("proxy"),
            "hosting": d.get("hosting"),
        }

    async def _from_ipwho(self, client: httpx.AsyncClient, ip: str) -> dict | None:
        try:
            d = (await client.get(f"https://ipwho.is/{quote(ip)}")).json()
        except (httpx.HTTPError, ValueError):
            return None
        if not d.get("success", False):
            return None
        conn = d.get("connection") or {}
        tz = d.get("timezone") or {}
        asn = conn.get("asn")
        return {
            "source": "ipwho.is",
            "country": d.get("country"),
            "country_code": d.get("country_code"),
            "region": d.get("region"),
            "city": d.get("city"),
            "postal": d.get("postal"),
            "lat": d.get("latitude"),
            "lon": d.get("longitude"),
            "timezone": tz.get("id") if isinstance(tz, dict) else None,
            "isp": conn.get("isp"),
            "org": conn.get("org"),
            "asn": (f"AS{asn} {conn.get('org') or ''}".strip() if asn else None),
        }

    async def _from_geojs(self, client: httpx.AsyncClient, ip: str) -> dict | None:
        try:
            d = (await client.get(f"https://get.geojs.io/v1/ip/geo/{quote(ip)}.json")).json()
        except (httpx.HTTPError, ValueError):
            return None
        if not d.get("country"):
            return None
        return {
            "source": "geojs.io",
            "country": d.get("country"),
            "country_code": d.get("country_code"),
            "region": d.get("region"),
            "city": d.get("city"),
            "lat": d.get("latitude"),
            "lon": d.get("longitude"),
            "timezone": d.get("timezone"),
            "isp": d.get("organization_name"),
            "org": d.get("organization_name"),
            "asn": d.get("organization"),  # already "AS<n> <name>"
        }

    async def _from_rfg(self, client: httpx.AsyncClient, ip: str) -> dict | None:
        try:
            d = (await client.get(f"https://reallyfreegeoip.org/json/{quote(ip)}")).json()
        except (httpx.HTTPError, ValueError):
            return None
        if not d.get("country_name"):
            return None
        return {
            "source": "reallyfreegeoip.org",
            "country": d.get("country_name"),
            "country_code": d.get("country_code"),
            "region": d.get("region_name"),
            "city": d.get("city"),
            "postal": d.get("zip_code"),
            "lat": d.get("latitude"),
            "lon": d.get("longitude"),
            "timezone": d.get("time_zone"),
        }

    async def _geolocate(self, ip: str) -> list[Finding]:
        client = get_client()
        providers = [self._from_ipwho, self._from_geojs, self._from_rfg]
        # ip-api.com is HTTP-only on the free plan: opt-out available.
        if settings.enable_insecure_ipapi:
            providers.insert(0, self._from_ipapi)

        recs = await asyncio.gather(*(p(client, ip) for p in providers))
        sources = [r for r in recs if r]
        if not sources:
            return []

        findings: list[Finding] = []
        names = ", ".join(r["source"] for r in sources)
        findings.append(
            Finding(
                label="Geolocation sources", value=f"{len(sources)} ({names})", category="geo", confidence=0.9
            )
        )
        if any(r["source"] == "ip-api.com" for r in sources):
            findings.append(
                Finding(
                    label="Privacy notice",
                    value="ip-api.com was queried over plain HTTP (no HTTPS on its free plan): "
                    "the looked-up address travelled unencrypted",
                    category="geo",
                    confidence=0.95,
                )
            )

        def field(key):
            return [str(r[key]) for r in sources if r.get(key)]

        # --- Country / region / city by majority vote ---
        cwin, cc, ct = _vote(field("country"))
        if cwin:
            code = _vote(field("country_code"))[0]
            agree = f" · {cc}/{ct} sources agree" if ct > 1 else ""
            findings.append(
                Finding(
                    label="Country",
                    value=cwin + (f" ({code})" if code else "") + agree,
                    category="geo",
                    confidence=_conf(cc, ct, 0.55, 0.4),
                )
            )

        for label, key, base, span in (("Region", "region", 0.45, 0.4), ("City", "city", 0.4, 0.4)):
            win, c, t = _vote(field(key))
            if win:
                agree = f" · {c}/{t} agree" if t > 1 else " · 1 source"
                findings.append(
                    Finding(
                        label=label, value=win + agree, category="geo", confidence=_conf(c, t, base, span)
                    )
                )

        # --- Coordinates: centroid + spread (precision indicator) ---
        # Only trust a source's coordinates if it also reports a city; a bare
        # lat/lon with no city is usually the provider's country-center fallback.
        pts = []
        for r in sources:
            if r.get("lat") is None or r.get("lon") is None or not (r.get("city") or "").strip():
                continue
            try:
                pts.append((float(r["lat"]), float(r["lon"])))
            except (TypeError, ValueError):
                pass
        if pts:
            clat = sum(p[0] for p in pts) / len(pts)
            clon = sum(p[1] for p in pts) / len(pts)
            spread = max((_haversine((clat, clon), p) for p in pts), default=0.0)
            coord_conf = (0.8 if spread <= 25 else 0.45) if len(pts) > 1 else 0.55
            findings.append(
                Finding(
                    label="Coordinates",
                    value=f"{clat:.4f}, {clon:.4f}" + (f" (avg of {len(pts)})" if len(pts) > 1 else ""),
                    category="geo",
                    confidence=coord_conf,
                )
            )
            if len(pts) > 1:
                if spread <= 25:
                    findings.append(
                        Finding(
                            label="Coordinate agreement",
                            value=f"{len(pts)} sources within ~{spread:.0f} km (consistent)",
                            category="geo",
                            confidence=0.8,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            label="Coordinate agreement",
                            value=f"Sources differ by ~{spread:.0f} km "
                            "(approximate — likely city-level guess)",
                            category="geo",
                            confidence=0.4,
                        )
                    )
            findings.append(
                Finding(
                    label="Map",
                    value=f"https://www.openstreetmap.org/?mlat={clat:.4f}&mlon={clon:.4f}#map=11/{clat:.4f}/{clon:.4f}",
                    category="pivot",
                    confidence=0.6,
                )
            )

        # --- Postal / timezone consensus ---
        for label, key in (("Postal code", "postal"), ("Timezone", "timezone")):
            win, c, t = _vote(field(key))
            if win:
                findings.append(
                    Finding(label=label, value=win, category="geo", confidence=_conf(c, t, 0.5, 0.35))
                )

        # --- Network ownership (RIR data — reliable) ---
        for label, key in (("ISP", "isp"), ("Organization", "org"), ("ASN", "asn")):
            win, c, t = _vote(field(key))
            if win:
                findings.append(
                    Finding(label=label, value=win, category="network", confidence=_conf(c, t, 0.7, 0.25))
                )

        # --- Threat / usage signals (from ip-api) ---
        ipapi = next((r for r in sources if r["source"] == "ip-api.com"), {})
        if ipapi.get("reverse"):
            findings.append(Finding(label="Reverse DNS (ip-api)", value=ipapi["reverse"], category="ip"))
        signals = (
            ("Mobile network", "mobile"),
            ("Proxy / VPN / Tor", "proxy"),
            ("Hosting / datacenter", "hosting"),
        )
        for label, key in signals:
            if ipapi.get(key) is True:
                findings.append(Finding(label=label, value="Yes", category="reputation", confidence=0.8))
        return findings

    async def _reverse_dns(self, ip: str) -> list[Finding]:
        return [Finding(label="Reverse DNS (PTR)", value=name, category="ip") for name in await reverse(ip)]

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
        return [
            Finding(label=f"Look up on {name}", value=url, category="pivot", confidence=0.5)
            for name, url in links
        ]

    async def _run(self, target: str) -> list[Finding]:
        ip = target.strip()
        findings: list[Finding] = []
        findings += self._classify(ip)

        # Only query geo providers for globally routable addresses.
        try:
            is_global = ipaddress.ip_address(ip).is_global
        except ValueError:
            is_global = False
        if is_global:
            findings += await self._geolocate(ip)
        findings += await self._reverse_dns(ip)
        findings += self._pivots(ip)
        return findings
