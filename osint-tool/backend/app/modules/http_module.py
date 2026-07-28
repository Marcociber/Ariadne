"""
HTTP module (free, no API key required):
    - Fetches the domain's home page and reports the live HTTP surface:
      final URL / redirect chain, status, server banner, page title.
    - Security header posture: HSTS, CSP, X-Frame-Options, X-Content-Type,
      Referrer-Policy, Permissions-Policy (present vs. missing).
    - Technology fingerprint inferred from response headers, cookies and the
      parsed HTML (generator meta, script/link sources).

Everything is read from the site's own live response — no third-party
service, no scraping of private data.

SECURITY: this is the only module that fetches an arbitrary user-supplied
host over HTTP, and the caller can force `target_type`, so
`{"target": "169.254.169.254", "target_type": "domain"}` used to make the
backend request the cloud metadata endpoint. Every request now goes through
`core.net.safe_fetch`, which resolves the name first, refuses non-global
addresses, validates each redirect hop and caps the response size.

HTML is parsed with selectolax instead of regular expressions.
"""

from selectolax.parser import HTMLParser

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType
from ..core.net import UnsafeTargetError, safe_fetch

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
    ("server", "caddy", "Caddy"),
    ("server", "gunicorn", "Gunicorn"),
    ("server", "openresty", "OpenResty"),
    ("server", "envoy", "Envoy"),
    ("server", "awselb", "AWS Elastic Load Balancer"),
    ("server", "gse", "Google Servers"),
    ("server", "akamai", "Akamai"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-powered-by", "express", "Express.js"),
    ("x-powered-by", "next.js", "Next.js"),
    ("x-powered-by", "nuxt", "Nuxt"),
    ("x-powered-by", "servlet", "Java Servlet"),
    ("x-generator", "drupal", "Drupal"),
    ("x-drupal-cache", "", "Drupal"),
    ("x-shopify-stage", "", "Shopify"),
    ("x-vercel-id", "", "Vercel"),
    ("x-nf-request-id", "", "Netlify"),
    ("x-github-request-id", "", "GitHub Pages"),
    ("x-served-by", "wordpress", "WordPress.com"),
    ("x-wix-request-id", "", "Wix"),
    ("x-hubspot-correlation-id", "", "HubSpot"),
    ("x-amz-cf-id", "", "Amazon CloudFront"),
    ("x-azure-ref", "", "Azure Front Door"),
    ("x-fastly-request-id", "", "Fastly"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-litespeed-cache", "", "LiteSpeed Cache"),
    ("x-cache", "cloudfront", "Amazon CloudFront"),
    ("cf-ray", "", "Cloudflare"),
    ("fly-request-id", "", "Fly.io"),
    ("x-render-origin-server", "", "Render"),
    ("x-runtime", "", "Ruby on Rails"),
]

# Cookie name fragments -> technology.
_COOKIE_HINTS = [
    ("wordpress", "WordPress"),
    ("wp-", "WordPress"),
    ("laravel_session", "Laravel"),
    ("xsrf-token", "Laravel / Angular"),
    ("phpsessid", "PHP"),
    ("jsessionid", "Java"),
    ("asp.net_sessionid", "ASP.NET"),
    ("_shopify", "Shopify"),
    ("django", "Django"),
    ("csrftoken", "Django"),
    ("ci_session", "CodeIgniter"),
    ("prestashop", "PrestaShop"),
    ("__cfduid", "Cloudflare"),
    ("ahoy_visitor", "Ruby on Rails"),
]

# Markers inside the HTML body -> technology.
_HTML_HINTS = [
    ("/wp-content/", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("/sites/default/files/", "Drupal"),
    ("/media/jui/", "Joomla"),
    ("cdn.shopify.com", "Shopify"),
    ("/_next/static/", "Next.js"),
    ("/_nuxt/", "Nuxt"),
    ("__NEXT_DATA__", "Next.js"),
    ("ng-version", "Angular"),
    ("data-reactroot", "React"),
    ("/static/js/", "Single-page app bundle"),
    ("squarespace", "Squarespace"),
    ("wix.com", "Wix"),
    ("webflow", "Webflow"),
    ("googletagmanager.com", "Google Tag Manager"),
    ("google-analytics.com", "Google Analytics"),
    ("hotjar", "Hotjar"),
    ("cdn.jsdelivr.net", "jsDelivr CDN"),
    ("bootstrap", "Bootstrap"),
    ("jquery", "jQuery"),
]


@register
class HTTPModule(OSINTModule):
    name = "http"
    supported_types = [TargetType.DOMAIN]

    async def _run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            result = await safe_fetch(f"https://{target}")
        except UnsafeTargetError as exc:
            # Refusing is a real, reportable outcome, not a silent skip.
            return [
                Finding(
                    label="Website not fetched",
                    value=f"Refused: {exc}",
                    category="web_security",
                    confidence=0.9,
                )
            ]
        except Exception:
            try:
                result = await safe_fetch(f"http://{target}")
            except UnsafeTargetError as exc:
                return [
                    Finding(
                        label="Website not fetched",
                        value=f"Refused: {exc}",
                        category="web_security",
                        confidence=0.9,
                    )
                ]
            except Exception:
                return [
                    Finding(
                        label="Website reachable",
                        value="No (no HTTP response)",
                        category="web",
                        confidence=0.9,
                    )
                ]

        findings.append(Finding(label="Website reachable", value="Yes", category="web"))
        findings.append(Finding(label="HTTP status", value=str(result.status_code), category="web"))

        if result.redirects:
            findings.append(
                Finding(
                    label="Final URL (after redirects)",
                    value=result.url,
                    category="web",
                    confidence=0.9,
                )
            )
            findings.append(Finding(label="Redirects", value=str(len(result.redirects)), category="web"))

        headers = result.headers
        if headers.get("server"):
            findings.append(Finding(label="Server", value=headers["server"], category="web"))
        if headers.get("x-powered-by"):
            findings.append(Finding(label="Powered by", value=headers["x-powered-by"], category="web"))

        findings += self._from_html(result.text)
        findings += self._fingerprint(headers, result.text)
        findings += self._security_headers(headers)
        return findings

    # ------------------------------------------------------------------ HTML
    def _from_html(self, body: str) -> list[Finding]:
        """Title, description and generator, parsed properly (no regex)."""
        if not body:
            return []
        findings: list[Finding] = []
        tree = HTMLParser(body)

        title_node = tree.css_first("title")
        if title_node:
            title = " ".join((title_node.text() or "").split())
            if title:
                findings.append(Finding(label="Page title", value=title[:150], category="web"))

        for node in tree.css("meta"):
            name = (node.attributes.get("name") or "").lower()
            content = (node.attributes.get("content") or "").strip()
            if not content:
                continue
            if name == "generator":
                findings.append(
                    Finding(
                        label="Generator (meta)",
                        value=content[:100],
                        category="tech",
                        confidence=0.9,
                    )
                )
            elif name == "description":
                findings.append(
                    Finding(
                        label="Meta description",
                        value=content[:200],
                        category="web",
                        confidence=0.9,
                    )
                )

        root = tree.css_first("html")
        lang = (root.attributes.get("lang") if root else None) or ""
        if lang.strip():
            findings.append(
                Finding(
                    label="Declared language",
                    value=lang.strip(),
                    category="web",
                    confidence=0.8,
                )
            )
        return findings

    # ----------------------------------------------------------- fingerprint
    def _fingerprint(self, headers: dict[str, str], body: str) -> list[Finding]:
        detected: set[str] = set()
        for hkey, needle, tech in _TECH_HINTS:
            hv = headers.get(hkey)
            if hv is None:
                continue
            if needle == "" or needle in hv.lower():
                detected.add(tech)

        set_cookie = headers.get("set-cookie", "").lower()
        for needle, tech in _COOKIE_HINTS:
            if needle in set_cookie:
                detected.add(tech)

        low_body = body[:200_000].lower()
        for needle, tech in _HTML_HINTS:
            if needle.lower() in low_body:
                detected.add(tech)

        return [
            Finding(label="Technology", value=tech, category="tech", confidence=0.8)
            for tech in sorted(detected)
        ]

    # ------------------------------------------------------- security headers
    def _security_headers(self, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        present: list[str] = []
        missing: list[str] = []
        for hkey, nice in _SECURITY_HEADERS.items():
            (present if hkey in headers else missing).append(nice)
        findings += [
            Finding(
                label="Security header",
                value=f"{nice} ✓",
                category="web_security",
                confidence=0.9,
            )
            for nice in present
        ]
        if missing:
            findings.append(
                Finding(
                    label="Missing security headers",
                    value=", ".join(missing),
                    category="web_security",
                    confidence=0.9,
                )
            )
        return findings
