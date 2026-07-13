# 🔍 OSINT All-in-One

Open-source intelligence dashboard that aggregates **multiple free sources** into a single API and unified panel. Enter a target — domain, email, username, or phone — and the tool auto-detects the type, runs all compatible sources in **parallel**, normalizes the results, and correlates data across modules.

> ⚠️ **Ethical use.** This tool only queries **public** information. Use it only on targets you own or are authorized to scan. Respect each source's Terms of Service and applicable law. The author is not responsible for misuse.

---

## ✨ Features

- **Target selection**: choose the type (domain, email, username, phone) with a selector, or leave it on **Auto** for automatic detection.
- **Country code selector**: when scanning a phone, a dropdown with +45 countries (flag + code) lets you enter only the local number.
- **Concurrent execution**: all sources run in parallel using `asyncio`.
- **Plugin architecture**: adding a new source is creating one class; you do not touch the core.
- **Normalized output**: every source returns the same structure (`Finding`), ready for the frontend.
- **No false positives**: every item comes from a verifiable response (authoritative DNS, HTTP 200 from Gravatar, exact match…). No guesswork.
- **Correlation engine**: cross-references data appearing in multiple sources.
- **Interactive graph view**: force-directed graph drawn on canvas (no libraries), with the target at the center, module branches, and correlated nodes highlighted.
- **Animated background**: node network on canvas (ARIADNE philosophy — the thread that connects data) using the same palette as the graph.
- **Resilient**: if one source fails or is slow, the rest of the scan continues (crt.sh even retries transient 502s).
- **100% free**: no API key required to run.

## 🧩 Included sources (no API key)

| Target     | Module    | What it collects                                                                                      |
|------------|-----------|--------------------------------------------------------------------------------------------------------|
| Domain     | `dns`     | A, AAAA, MX, NS, TXT, **SOA, CAA** records; **DMARC** policy; labeled **SPF**; **Reverse DNS (PTR)**        |
| Domain     | `whois`   | Registrar, WHOIS server, dates (creation/update/expiration), **days until expiration**, **EPP status**, **DNSSEC**, nameservers, registrant, location, emails |
| Domain     | `crtsh`   | Subdomains via Certificate Transparency + **count** and **issuing CAs**                                  |
| Email      | `email`   | Gravatar (avatar, name, **location, bio, links**), **known provider**, **MX**, **SPF/DMARC** of the domain |
| Username   | `username`| Presence on 150+ platforms via **Maigret** (real detection) + **profile count**                        |
| Phone      | `phone`   | Validity, formats (E.164/intl/national), country + **flag**, region, **carrier** (mobile only), timezone, line type, length, and **pivot links** (WhatsApp/Telegram/Truecaller/search) filtered by line type |

> Paid modules (HIBP, Shodan, Hunter.io…) can be added as optional plugins using `.env`. The architecture already supports them through the `requires_key` flag.

## 🖼️ Graph view

The dashboard includes a graph view (force-directed, drawn on canvas without external libraries) that places the target at the center, branches each module, and highlights correlated nodes between sources.

![Domain graph](docs/graph-domain.png)

*Example with a domain: yellow nodes with white borders (`ns1.example.com`, `mail.example.com`) appear in two sources at once.*

![Phone graph](docs/graph-phone.png)

*Example with a phone: one module with multiple attributes.*

## 🏗️ Architecture

```
Frontend (dashboard)
        │  POST /scan
        ▼
FastAPI ──▶ Type detector ──▶ Async orchestrator
                                      │  (runs compatible modules in parallel)
                ┌─────────────┬───────┼────────┬──────────┐
              dns          whois    crtsh    email  username  phone   ← plugins
                └─────────────┴───────┼────────┴──────────┘
                                      ▼
                         Normalizer (Pydantic)
                                      ▼
                          Correlation engine
                                      ▼
                            Unified JSON response
```

## 🚀 Getting started

### Option A — Docker (recommended)

```bash
docker compose up --build
```

- API:       http://localhost:8000  (interactive docs at `/docs`)
- Dashboard: http://localhost:8080

### Option B — Local

**Backend:**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Frontend:** open `frontend/index.html` in your browser (or serve it with any static server). Point it to `http://127.0.0.1:8000`.

## 📡 API

| Method | Path       | Description                          |
|--------|------------|--------------------------------------|
| GET    | `/health`  | Healthcheck                          |
| GET    | `/modules` | List available modules and supported types |
| POST   | `/scan`    | Scan a target                        |

The `/scan` body accepts:

| Field         | Type   | Required | Description                                                                 |
|---------------|--------|----------|-----------------------------------------------------------------------------|
| `target`      | string | Yes      | The target to scan.                                                          |
| `target_type` | string | No       | Force the type (`domain`/`email`/`username`/`phone`). If omitted or `auto`, it autodetects. |

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

## ➕ Adding a new source

1. Create `backend/app/modules/my_source.py`:

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

2. Import it in `backend/app/modules/__init__.py`.

That is all — the orchestrator detects it and uses it automatically.

## 🗺️ Roadmap

- [x] ~~Visual graph of entity relationships.~~ ✅
- [x] ~~Maigret username module integration.~~ ✅
- [x] ~~Target type selector + country code dropdown.~~ ✅
- [x] ~~Enhanced modules (DMARC/SPF/PTR, DNSSEC, CAs, phone pivots…).~~ ✅
- [ ] Redis cache to avoid repeated queries.
- [ ] Scan history in PostgreSQL.
- [ ] Optional paid plugins (Shodan, HIBP) toggleable via `.env`.
- [ ] Export reports (JSON / PDF).

## ⚙️ Username module configuration (Maigret)

The `username` module uses [Maigret](https://github.com/soxoj/maigret) and supports two optional environment variables:

| Variable            | Default | Description                                             |
|---------------------|---------|---------------------------------------------------------|
| `MAIGRET_TOP_SITES` | `150`   | Number of top-ranked sites to check                      |
| `MAIGRET_TIMEOUT`   | `10`    | Timeout per site, in seconds                             |

Increasing `MAIGRET_TOP_SITES` improves coverage but slows scans.

## 📄 License

MIT. See the `LICENSE` file.
