"""
HTTP module (free, no API key required):
    - Fetches the domain's home page and reports the live HTTP surface:
      final URL / redirect chain, status, server banner, page title.
    - Security header posture: HSTS, CSP, X-Frame-Options, X-Content-Type,
      Referrer-Policy, Permissions-Policy (present vs. missing).
    - Lightweight technology fingerprint inferred from response headers,
      cookies and the HTML `generator` meta tag (WordPress, Cloudflare…).

Everything is read from the site's own live response — no third-party
service, no scraping of private data.
"""
import re

import httpx

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)

# Recommended security headers -> friendly name.
_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# Header/cookie signatures -> technology.
_TECH_HINTS = [
    ("server", "cloudflare", "Cloudflare"),
    ("server", "nginx", "nginx"),
    ("server", "apache", "Apache"),
    ("server", "microsoft-iis", "Microsoft IIS"),
    ("server", "litespeed", "LiteSpeed"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-powered-by", "express", "Express.js"),
    ("x-powered-by", "next.js", "Next.js"),
    ("x-generator", "drupal", "Drupal"),
    ("x-shopify-stage", "", "Shopify"),
    ("x-vercel-id", "", "Vercel"),
    ("x-github-request-id", "", "GitHub Pages"),
    ("x-served-by", "wordpress", "WordPress.com"),
    ("cf-ray", "", "Cloudflare"),
]


@register
class HTTPModule(OSINTModule):
    name = "http"
    supported_types = [TargetType.DOMAIN]

    async def _run(self, target: str) -> list[Finding]:
        url = f"https://{target}"
        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; osint-tool/1.0)"},
            ) as client:
                resp = await client.get(url)
        except httpx.HTTPError:
            # Retry once over plain HTTP before giving up.
            try:
                async with httpx.AsyncClient(
                    timeout=10.0, follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; osint-tool/1.0)"},
                ) as client:
                    resp = await client.get(f"http://{target}")
            except httpx.HTTPError:
                return [Finding(label="Website reachable", value="No (no HTTP response)", category="web", confidence=0.9)]

        findings.append(Finding(label="Website reachable", value="Yes", category="web"))
        findings.append(Finding(label="HTTP status", value=str(resp.status_code), category="web"))

        final = str(resp.url)
        if final.rstrip("/") not in (url, f"http://{target}"):
            findings.append(Finding(label="Final URL (after redirects)", value=final, category="web", confidence=0.9))
        if len(resp.history) > 0:
            findings.append(Finding(label="Redirects", value=str(len(resp.history)), category="web"))

        headers = {k.lower(): v for k, v in resp.headers.items()}
        if headers.get("server"):
            findings.append(Finding(label="Server", value=headers["server"], category="web"))
        if headers.get("x-powered-by"):
            findings.append(Finding(label="Powered by", value=headers["x-powered-by"], category="web"))

        # Page title + generator (best-effort HTML parse).
        body = resp.text[:200_000] if resp.text else ""
        m = _TITLE_RE.search(body)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
            if title:
                findings.append(Finding(label="Page title", value=title[:150], category="web"))
        g = _GENERATOR_RE.search(body)
        if g:
            findings.append(Finding(label="Generator (meta)", value=g.group(1).strip()[:100], category="tech", confidence=0.9))

        # Technology fingerprint from headers.
        detected: set[str] = set()
        for hkey, needle, tech in _TECH_HINTS:
            hv = headers.get(hkey)
            if hv is None:
                continue
            if needle == "" or needle in hv.lower():
                detected.add(tech)
        set_cookie = headers.get("set-cookie", "").lower()
        if "wordpress" in set_cookie or "wp-" in set_cookie:
            detected.add("WordPress")
        if "laravel_session" in set_cookie:
            detected.add("Laravel")
        for tech in sorted(detected):
            findings.append(Finding(label="Technology", value=tech, category="tech", confidence=0.8))

        # Security headers: present ones, then a summary of missing ones.
        present, missing = [], []
        for hkey, nice in _SECURITY_HEADERS.items():
            (present if hkey in headers else missing).append(nice)
        for nice in present:
            findings.append(Finding(label="Security header", value=f"{nice} ✓", category="web_security", confidence=0.9))
        if missing:
            findings.append(Finding(
                label="Missing security headers", value=", ".join(missing),
                category="web_security", confidence=0.9))

        return findings
