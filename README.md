# 🔍 OSINT All-in-One

Open-source intelligence dashboard that aggregates **multiple free sources** into a single API and unified panel. Enter a target — domain, email, username, phone or IP — and the tool auto-detects the type, runs all compatible sources in **parallel**, normalizes the results, and correlates data across modules.

> ⚠️ **Ethical use.** This tool only queries **public** information. Use it only on targets you own or are authorized to scan. Respect each source's Terms of Service and applicable law. The author is not responsible for misuse.

---

## ✨ Features

- **Target selection**: choose the type (domain, email, username, phone, **IP**) with a selector, or leave it on **Auto** for automatic detection. URLs, `mailto:` links, internationalized domains and single-host CIDRs are normalized automatically, and an unrecognized target now says **why** it was not recognized.
- **Country code selector**: when scanning a phone, a searchable dropdown with +45 countries (flag + code) lets you enter only the local number. Fully keyboard-navigable.
- **Live progress**: scans stream over **Server-Sent Events** — each source appears the moment it finishes, with an elapsed timer and a **Cancel** button, instead of a frozen spinner.
- **Search & filter results**: a live search box filters every finding across all modules (by label or value, with match highlighting), plus one-click **category filters** and a **summary** (findings, sources with data, categories, scan time).
- **Readable UI**: light/dark **theme toggle** (persisted), collapsible module cards, per-finding **copy-to-clipboard** and **pivot** (scan a finding as the next target), per-module timings and error messages, per-finding **confidence** indicator, and a fully responsive, accessible layout.
- **Concurrent execution**: all sources run in parallel using `asyncio`, under a global scan deadline and a per-module timeout.
- **Plugin architecture**: adding a new source is creating one class; you do not touch the core. See [CONTRIBUTING.md](CONTRIBUTING.md).
- **Normalized output**: every source returns the same structure (`Finding`), ready for the frontend.
- **No false positives**: every item comes from a verifiable response (authoritative DNS, HTTP 200 from Gravatar, label-boundary subdomain matching via the Public Suffix List…). No guesswork.
- **Typed correlation engine**: cross-references data appearing in multiple sources, normalizing case, trailing DNS dots, `www.` prefixes and IPv6 spellings, then labels each link (same IP, same nameserver, same mail host, same email, same organization…) with a weight. Fuzzy matching catches near-identical entity names.
- **Interactive graph view**: force-directed graph drawn on canvas (no libraries), with the target at the center, module branches, correlated nodes highlighted, **zoom/pan**, and click-to-fold sources. Uses a Barnes-Hut quadtree so hundreds of subdomains stay usable.
- **Animated background**: node network on canvas (ARIADNE philosophy — the thread that connects data), which pauses on hidden tabs and respects `prefers-reduced-motion`.
- **Resilient**: if one source fails or is slow, the rest of the scan continues (crt.sh even retries transient 502s), and a hung source is cut off rather than holding the request open.
- **Safe by default**: outbound requests to user-supplied hosts are blocked from reaching private, loopback or cloud-metadata addresses.
- **100% free**: no API key required to run.

## 🧩 Included sources (no API key)

| Target     | Module    | What it collects                                                                                      |
|------------|-----------|--------------------------------------------------------------------------------------------------------|
| Domain     | `dns`     | A, AAAA, MX, NS, TXT, **SOA, CAA** records; **DMARC** policy; labeled **SPF**; **Reverse DNS (PTR)**; **MTA-STS / TLS-RPT / BIMI**; **DNSSEC**; **www** host; recognized **service-verification tokens** (Google/Microsoft/Facebook/Stripe…). Falls back to **DNS-over-HTTPS** when the local resolver cannot answer |
| Domain     | `whois`   | Registrar (+ **URL**), WHOIS server, dates (creation/update/expiration), **days until expiration**, **domain age**, **EPP status**, **DNSSEC**, nameservers, registrant, location, emails |
| Domain     | `rdap`    | **Structured registry data** (JSON, not free-form text): registry ID, canonical name, registration/expiration/transfer events, explained **EPP status codes**, nameservers, DNSSEC delegation, registrar + IANA ID, **abuse contact** |
| Domain     | `crtsh`   | Subdomains via Certificate Transparency + **count**, **cert entries**, **wildcard detection** and **issuing CAs**            |
| Domain     | `tls`     | The certificate **served right now**: validity for the hostname, issuer, subject, dates, **days to expiry**, serial, TLS version, cipher suite and every **SAN hostname** |
| Domain     | `http`    | Live HTTP surface: reachability, status, **redirect chain**, server banner, **page title**, **meta description**, **technology fingerprint** (~40 header/cookie/HTML signatures, parsed with a real HTML parser), and **security-header posture** (HSTS/CSP/X-Frame-Options… present vs. missing) |
| Domain     | `robots`  | **robots.txt** rules and disallowed paths — with admin/backup/staging paths surfaced separately — plus declared **sitemaps** and their entry count |
| Domain     | `wayback` | Internet Archive history: **first/last snapshot** dates, direct snapshot links, and a browse-all-captures pivot |
| Email      | `email`   | **Address analysis** (valid format, role-based/disposable, Gmail canonical form, plus-tag), Gravatar (avatar, name, **location, bio, links**, MD5+**SHA-256**), **mail provider (MX)**, whether the domain **hosts a website**, **SPF/DMARC/MTA-STS**, and **pivots** (candidate username, web/GitHub search) |
| Username   | `username`| Presence on many platforms via **Maigret** (real detection) + **profile count**. Site count configurable globally and per scan |
| Username   | `github`  | Public **GitHub profile** (name, bio, company, location, blog, Twitter), activity (repos, gists, followers, created/last-active dates) and **recent repositories** — GitHub's own API, no key. Rate limiting is reported explicitly instead of looking like "no such user" |
| Phone      | `phone`   | Validity, formats (E.164/intl/national), country + **flag**, region, **carrier** (mobile only), timezone, line type, length, and **pivot links** (WhatsApp/Telegram/Truecaller/**Sync.me**/**Facebook**/search) filtered by line type |
| IP         | `ip`      | Address scope (public/private/reserved), **multi-source geolocation by consensus** (ip-api.com + ipwho.is + geojs.io + reallyfreegeoip.org — agreement raises confidence, coordinate spread flags approximate fixes), ISP/**ASN**, **reverse DNS (PTR)**, mobile/proxy/hosting flags, and reputation **pivots** (Shodan/Censys/VirusTotal/AbuseIPDB/GreyNoise) |

> **Key-based modules** (`shodan`, `hibp`) are already included as optional plugins — they activate automatically when you set their API key. See [Optional key-based modules](#-optional-key-based-modules).

## 🖼️ Graph view

The dashboard includes a graph view (force-directed, drawn on canvas without external libraries) that places the target at the center, branches each module, and highlights correlated nodes between sources. Scroll to zoom, drag to pan, drag a node to reposition it, and click a source node to fold its findings away.

![Domain graph](osint-tool/docs/graph-domain.png)

*Example with a domain: yellow nodes with white borders (`ns1.example.com`, `mail.example.com`) appear in two sources at once.*

![Phone graph](osint-tool/docs/graph-phone.png)

*Example with a phone: one module with multiple attributes.*

## 🏗️ Architecture

```
Frontend (dashboard)            index.html + assets/styles.css + assets/app.js
        │  POST /scan  ·  GET /scan/stream (SSE)
        ▼
FastAPI ──▶ Type detector ──▶ Async orchestrator
   │                                  │  (runs compatible modules in parallel,
   │                                  │   under a global deadline)
   │            ┌─────────┬───────────┼───────────┬─────────┐
   │          dns  whois  rdap  crtsh  tls  http  robots  …   ← plugins
   │            └─────────┴───────────┼───────────┴─────────┘
   │                                  ▼
   │                     Normalizer (Pydantic)
   │                                  ▼
   │                      Correlation engine (typed + weighted)
   │                                  ▼
   │                        Unified JSON response
   ├─▶ Redis cache (optional, async)
   └─▶ SQLite history (retention + pagination)
```

## 🚀 Getting started

### Option A — Docker (recommended)

```bash
cd osint-tool
docker compose up --build
```

- API:       http://localhost:8000  (interactive docs at `/docs`)
- Dashboard: http://localhost:8080

The compose file wires Redis, a persistent history volume, healthchecks, resource limits and an nginx config that serves the dashboard with security headers and a Content-Security-Policy.

### Option B — Local

**Backend:**
```bash
cd osint-tool/backend
python -m venv .venv && source .venv/bin/activate   # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Frontend:** open `index.html` (at the repo root) in your browser, or serve the repo root with any static server. It defaults to `http://127.0.0.1:8000`; if your backend lives elsewhere, set the URL in the **⚙ Settings** panel (see [Configuring the frontend](#-configuring-the-frontend)).

## 📡 API

| Method | Path                | Description                                            |
|--------|---------------------|--------------------------------------------------------|
| GET    | `/health`           | Healthcheck (never authenticated or rate-limited)      |
| GET    | `/modules`          | List modules, supported types and whether each is available |
| POST   | `/scan`             | Scan a target                                          |
| GET    | `/scan/stream`      | Same scan, streamed per module as Server-Sent Events   |
| GET    | `/history`          | List recent scans (newest first). Query: `?limit=50&offset=0` |
| GET    | `/history/{id}`     | Retrieve a stored scan by id                           |
| DELETE | `/history/{id}`     | Forget a stored scan                                   |

The `/scan` body accepts:

| Field         | Type   | Required | Description                                                                 |
|---------------|--------|----------|-----------------------------------------------------------------------------|
| `target`      | string | Yes      | The target to scan (1–253 characters).                                       |
| `target_type` | enum   | No       | Force the type: `domain`, `email`, `username`, `phone`, `ip`. Omit it or send `auto` to autodetect. Any other value is rejected with a 422. |
| `refresh`     | bool   | No       | Skip the cache and query every source again. Default `false`.                |
| `max_sites`   | int    | No       | Override the number of sites the `username` module checks, for this scan only. |

**Example (auto-detect):**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "github.com"}'
```

**Example (forced type):**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "torvalds", "target_type": "username"}'
```

**Example (streaming progress):**
```bash
curl -N "http://localhost:8000/scan/stream?target=github.com"
```

## ➕ Adding a new source

1. Create `osint-tool/backend/app/modules/my_source.py`:

```python
from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType

@register
class MySource(OSINTModule):
    name = "my_source"
    supported_types = [TargetType.DOMAIN]

    async def _run(self, target: str) -> list[Finding]:
        # ... your logic ...
        return [Finding(label="Something", value="value", category="cat")]
```

2. Import it in `osint-tool/backend/app/modules/__init__.py`.

That is all — the orchestrator detects it and uses it automatically. [CONTRIBUTING.md](CONTRIBUTING.md) covers the conventions (and the one rule that matters: never fetch a user-supplied host without the SSRF guard).

## ⚙️ Configuration

All settings live in one typed object (`app/core/config.py`) and are read from the environment **or from `backend/.env`**, which is loaded automatically. Copy the template and edit what you need — every value has a working default:

```bash
cp osint-tool/backend/.env.example osint-tool/backend/.env
```

| Variable | Default | What it does |
|---|---|---|
| `SHODAN_API_KEY`, `HIBP_API_KEY` | unset | Activate the corresponding key-based module |
| `REDIS_URL` | unset | Enables the scan cache (no-op when unset or unreachable) |
| `CACHE_TTL` | `3600` | Seconds a cached scan stays valid |
| `HISTORY_DB` | `ariadne_history.db` | SQLite file for the scan history |
| `HISTORY_MAX_ROWS` / `HISTORY_RETENTION_DAYS` | `5000` / `90` | Retention policy, so the table cannot grow without bound |
| `SCAN_TIMEOUT` / `MODULE_TIMEOUT` / `WHOIS_TIMEOUT` | `120` / `60` / `20` | Hard deadlines, in seconds |
| `MAX_CONCURRENT_SCANS` | `4` | Simultaneous scans allowed |
| `MAIGRET_TOP_SITES` / `MAIGRET_TIMEOUT` | `75` / `10` | Username coverage vs. speed — the main driver of scan time |
| `CORS_ORIGINS` | `*` | Comma-separated browser origins allowed to call the API |
| `API_KEY` | unset | When set, every endpoint but `/health` requires the `X-API-Key` header |
| `RATE_LIMIT` / `SCAN_RATE_LIMIT` | `60/minute` / `10/minute` | Per-client request limits |
| `ALLOW_PRIVATE_TARGETS` | `false` | Lets modules fetch private/reserved addresses. Only on an isolated network |
| `ENABLE_INSECURE_IPAPI` | `true` | ip-api.com is HTTP-only on its free plan; set `false` to drop it |
| `LOG_LEVEL` / `LOG_JSON` | `INFO` / `false` | Structured logging (JSON for log collectors) |

### 🛡️ Before exposing the API to a network

The defaults are tuned for local use. For anything else, at minimum:

1. Set `CORS_ORIGINS` to your dashboard's origin. With `*` and no authentication, **any** website you visit can drive your backend and read your scan history.
2. Set `API_KEY`, and enter the same value in the dashboard's ⚙ Settings panel.
3. Keep `ALLOW_PRIVATE_TARGETS=false` so a forced `target_type` cannot make the backend reach internal services or cloud metadata endpoints.
4. Review `RATE_LIMIT` / `SCAN_RATE_LIMIT`: one username scan fans out to dozens of outbound requests, so an open API is a traffic amplifier against third parties.

## 🔑 Optional key-based modules

Some modules use paid / key-gated APIs. They stay **disabled** until you provide
their key, and activate automatically once it is set (no code changes needed):

| Module   | Target | Env var          | What it adds                                         |
|----------|--------|------------------|------------------------------------------------------|
| `shodan` | Domain | `SHODAN_API_KEY` | Resolved IP, organization, open ports, services, CVEs |
| `hibp`   | Email  | `HIBP_API_KEY`   | Whether the email appears in known data breaches      |

Put the key in `backend/.env` (or export it in your shell, or pass it through Docker).
`GET /modules` reports each module's `available` flag so you can see what's active, and a scan response lists any module it had to skip for a missing key.

## 🖥️ Configuring the frontend

The dashboard is a static page with no build step: `index.html` +
`assets/styles.css` + `assets/app.js`. The API URL is resolved at runtime, in
this order:

1. The **⚙ Settings** panel in the UI (stored in `localStorage`).
2. `window.ARIADNE_API` — copy `assets/config.js.example` to `assets/config.js` and load it before `app.js`.
3. The `<meta name="ariadne-api">` tag in `index.html`.
4. `http://127.0.0.1:8000`.

Deploy it to any static host (GitHub Pages, Cloudflare Pages, Netlify…); the
included workflow publishes it to GitHub Pages on every push to `main`.

## ⚡ Caching & 🕘 history

- **Redis cache (optional).** Set `REDIS_URL` (e.g. `redis://localhost:6379/0`) to
  cache scan results for `CACHE_TTL` seconds. Repeated scans of the same target
  return instantly and are flagged `cached` in the response. The cache key
  includes the active module set, so adding an API key does not keep serving a
  result computed without it. Use **↻ Refresh** in the UI (or `"refresh": true`)
  to force a re-scan. If Redis is unset or unreachable, caching is skipped —
  scans still work.
- **Persistent history.** Every scan is stored (SQLite by default, at `HISTORY_DB`).
  Browse it from the **🕘 History** button in the UI, or via `GET /history`.
  Entries can be deleted individually, and a retention policy keeps the table
  bounded.

The Docker setup wires Redis and a persistent history volume automatically.

## 📤 Export

From the results bar you can export any scan as **JSON**, **CSV**, **Markdown**,
or as a printable **PDF** (via the browser's print dialog).

## 🧪 Development

```bash
cd osint-tool/backend
pip install -r requirements.txt -r requirements-dev.txt

pytest                                   # tests (no network access required)
ruff check . && ruff format --check .    # lint + format
mypy app/core                            # type checking
bandit -c pyproject.toml -r app          # static security analysis
pip-audit -r requirements.txt            # dependency CVEs
```

Frontend: `npx eslint assets/` and `npx prettier --check assets/ index.html`.

CI runs all of the above on every push and pull request, builds and scans the
Docker image with Trivy, and audits the dashboard's accessibility with Pa11y.

## 🗺️ Roadmap

- [x] ~~Visual graph of entity relationships.~~ ✅
- [x] ~~Maigret username module integration.~~ ✅
- [x] ~~Target type selector + country code dropdown.~~ ✅
- [x] ~~Searchable phone picker with image-based country flags + digits-only input.~~ ✅
- [x] ~~Enhanced modules (DMARC/SPF/PTR, DNSSEC, CAs, phone pivots…).~~ ✅
- [x] ~~Redis cache to avoid repeated queries.~~ ✅
- [x] ~~Persistent scan history (SQLite by default; `HISTORY_DB` swappable).~~ ✅
- [x] ~~Optional paid plugins (Shodan, HIBP) toggleable via `.env`.~~ ✅
- [x] ~~Export reports (JSON / PDF).~~ ✅ — now CSV and Markdown too
- [x] ~~IP target type (geolocation, ASN, reverse DNS, reputation pivots).~~ ✅
- [x] ~~Key-free enrichment modules: HTTP/security headers, Wayback Machine, GitHub profile.~~ ✅
- [x] ~~Results search + category filters, summary, copy-to-clipboard, light/dark theme.~~ ✅
- [x] ~~Streaming scan progress (SSE) with per-module results and cancellation.~~ ✅
- [x] ~~Key-free sources: RDAP, live TLS certificate, robots.txt/sitemap, DoH fallback.~~ ✅
- [x] ~~Test suite + CI/CD, SSRF protection, rate limiting, configurable CORS and optional API key.~~ ✅
- [ ] Auth + multi-user workspaces (a single static `API_KEY` is available today).
- [ ] Scheduled re-scans with change alerts.

## 📄 License

MIT. See the `LICENSE` file.
