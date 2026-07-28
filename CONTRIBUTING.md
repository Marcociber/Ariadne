# Contributing to ARIADNE

The plugin architecture exists so that adding a source never means touching
the core. If that is what you want to do, jump straight to
[Adding a source](#adding-a-source).

---

## Ground rules

**1. No false positives.** This is the project's stated value proposition, and
it constrains every contribution. A finding must come from a verifiable
response — an authoritative DNS record, an HTTP 200, a parsed API payload —
never from a guess or a heuristic that "usually" holds. If the data is
uncertain, say so: lower the `confidence` and label it honestly (see the
carrier caveat in `phone_module.py`, which explicitly states that number
portability is not reflected).

**2. A source may never break the scan.** `OSINTModule.run()` already isolates
exceptions and enforces a timeout. Do not add bare `except: pass` around your
own logic — log through `app.core.logging.get_logger` so failures are
debuggable.

**3. Never fetch a user-supplied host directly.** Anything that resolves or
requests a target the caller controls goes through `app.core.net.safe_fetch`
or `resolve_public_ips`. These refuse private, loopback, link-local and
reserved addresses, and validate every redirect hop. Bypassing them
reintroduces a server-side request forgery hole.

**4. English in code and comments.** The README, docstrings and identifiers
are in English; keep new code consistent.

---

## Setting up

```bash
cd osint-tool/backend
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env          # optional; every value has a working default
uvicorn app.main:app --reload
```

The dashboard is `index.html` at the repository root. Open it directly, or
serve the root with any static server. If your backend is not on
`http://127.0.0.1:8000`, set the URL from the **⚙ Settings** panel.

## Before opening a pull request

```bash
cd osint-tool/backend
ruff check . && ruff format --check .   # lint + format
mypy app/core                            # types (strict on the core)
pytest                                   # tests
bandit -c pyproject.toml -r app          # static security analysis
pip-audit -r requirements.txt            # dependency CVEs
```

For the frontend:

```bash
npx eslint assets/
npx prettier --check assets/ index.html
```

CI runs exactly these commands.

---

## Adding a source

1. Create `osint-tool/backend/app/modules/my_source.py`:

```python
from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType
from ..core.net import get_client          # shared, pooled HTTP client


@register
class MySource(OSINTModule):
    name = "my_source"
    supported_types = [TargetType.DOMAIN]
    # requires_key = True                  # only for key-gated APIs
    # timeout = 30.0                       # only if the default is too tight

    async def _run(self, target: str) -> list[Finding]:
        resp = await get_client().get(f"https://api.example.com/{target}")
        if resp.status_code != 200:
            # Say WHY there is no data. An empty list is indistinguishable
            # from "nothing found", which is a different conclusion.
            return [Finding(label="my_source", value=f"API returned {resp.status_code}",
                            category="my_cat", confidence=0.9)]
        return [Finding(label="Something", value=resp.json()["x"], category="my_cat")]
```

2. Import it in `app/modules/__init__.py`.
3. Add a test in `tests/` — use `respx` to mock the HTTP calls; the suite must
   never touch the network.
4. Add a row to the source table in `README.md`.

That is all: the orchestrator discovers and runs it automatically.

### Conventions for findings

| Field        | Guidance                                                                 |
|--------------|--------------------------------------------------------------------------|
| `label`      | What the value *is*, in title case (`Registrar`, `MX server`).            |
| `value`      | The observed data. Only `http(s)://` values are rendered as links.        |
| `category`   | Reuse an existing one where you can: `dns`, `whois`, `cert`, `web`, `web_security`, `email_infra`, `email_security`, `social`, `geo`, `network`, `tech`, `pivot`. |
| `confidence` | `1.0` only for facts. Lower it for inference, and explain in the label.   |

`category="pivot"` is special: it means "a URL this tool constructed for you
to follow manually". Pivots are never queried and are excluded from the
correlation engine.

### Key-gated sources

Set `requires_key = True`, read the key from `app.core.config.settings`, and
override `is_available()`. Add the setting to `Settings` and to
`.env.example`. The module then activates on its own once the key is set, and
is skipped silently when it is not.

---

## Reporting a security issue

Please do not open a public issue for a vulnerability in ARIADNE itself.
Report it privately through GitHub's *Security → Report a vulnerability* on
the repository.
