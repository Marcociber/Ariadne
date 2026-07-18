"""
GitHub module (free, no API key required):
    - Public profile via the GitHub REST API (unauthenticated: 60 req/hour).
      Name, bio, company, location, blog, public repos/gists, followers,
      account creation date, verified links.
    - A short summary of the most recently pushed public repositories.

Only public data returned by GitHub's own API — no scraping, no guesswork.
Runs on the `username` target type alongside Maigret, adding depth for one
of the most common OSINT pivots.
"""
import httpx

from ..core.base import OSINTModule, register
from ..core.models import Finding, TargetType

_HEADERS = {
    "User-Agent": "osint-tool",
    "Accept": "application/vnd.github+json",
}


@register
class GitHubModule(OSINTModule):
    name = "github"
    supported_types = [TargetType.USERNAME]

    async def _run(self, target: str) -> list[Finding]:
        user = target.strip().lstrip("@")
        if not user:
            return []

        async with httpx.AsyncClient(timeout=10.0, headers=_HEADERS) as client:
            resp = await client.get(f"https://api.github.com/users/{user}")
            # 404 = no such user; 403 = rate-limited. Either way, no data.
            if resp.status_code != 200:
                return []
            data = resp.json()
            repos: list[dict] = []
            try:
                r2 = await client.get(
                    f"https://api.github.com/users/{user}/repos",
                    params={"sort": "pushed", "per_page": 5},
                )
                if r2.status_code == 200:
                    repos = r2.json()
            except httpx.HTTPError:
                pass

        if data.get("type") and data["type"] != "User":
            kind = data["type"]  # Organization / Bot
        else:
            kind = "User"

        findings: list[Finding] = [
            Finding(label="GitHub profile", value=data.get("html_url", f"https://github.com/{user}"), category="social", confidence=0.95),
            Finding(label="Account type", value=kind, category="social"),
        ]

        def add(label, key, category="social", link=False):
            v = data.get(key)
            if v:
                findings.append(Finding(label=label, value=str(v), category=category))

        add("Name", "name")
        if data.get("company"):
            findings.append(Finding(label="Company", value=data["company"], category="social"))
        add("Location", "location", category="geo")
        if data.get("bio"):
            findings.append(Finding(label="Bio", value=str(data["bio"])[:200], category="social"))
        blog = (data.get("blog") or "").strip()
        if blog:
            if not blog.startswith("http"):
                blog = "https://" + blog
            findings.append(Finding(label="Website", value=blog, category="social"))
        if data.get("twitter_username"):
            findings.append(Finding(
                label="Twitter / X", value=f"https://twitter.com/{data['twitter_username']}",
                category="social"))
        if data.get("email"):
            findings.append(Finding(label="Public email", value=data["email"], category="social", confidence=0.9))

        # Activity signals (real counts from the API).
        for label, key in (("Public repositories", "public_repos"),
                            ("Public gists", "public_gists"),
                            ("Followers", "followers"),
                            ("Following", "following")):
            if data.get(key) is not None:
                findings.append(Finding(label=label, value=str(data[key]), category="activity"))

        if data.get("created_at"):
            findings.append(Finding(label="Account created", value=data["created_at"][:10], category="activity"))
        if data.get("updated_at"):
            findings.append(Finding(label="Last activity", value=data["updated_at"][:10], category="activity", confidence=0.8))

        # Most recently pushed repos — a quick view of what they work on.
        for repo in repos[:5]:
            name = repo.get("name")
            if not name:
                continue
            lang = repo.get("language")
            stars = repo.get("stargazers_count", 0)
            extra = " · ".join(filter(None, [lang, f"★{stars}" if stars else None]))
            label = f"Repo {name}" + (f" ({extra})" if extra else "")
            findings.append(Finding(label=label, value=repo.get("html_url", ""), category="repo", confidence=0.9))

        return findings
