"""Sync per-repository GitHub Security Advisories for a curated repo list.

Different from the `ghsa` source: `ghsa` pulls the GLOBAL GitHub Advisory Database
(github/advisory-database, ecosystem-scoped, reviewed only). This one pulls the
PER-REPOSITORY advisories via the REST API
    GET /repos/{owner}/{repo}/security-advisories
which is the only place repo-level advisories for NON-ecosystem software (desktop apps,
firmware, standalone binaries) exist — they never make it into the global feed.

The repo list is config/github_repos.json. Auth via GITHUB_TOKEN (5000 req/h vs 60/h
unauthenticated). One JSON file per repo is written to /data/github_repo/, re-read whole
on ingest (delete_scope makes it idempotent).
"""
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

_CONF = Path(__file__).resolve().parents[3] / "config" / "github_repos.json"
_API  = ("https://api.github.com/repos/{repo}/security-advisories"
         "?per_page=100&state=published&sort=published&page={page}")


def _load_repos():
    if not _CONF.exists():
        print(f"  github_repo: no config at {_CONF}")
        return []
    return [r for r in (json.loads(_CONF.read_text()).get("repos") or []) if isinstance(r, str)]


def _fetch(repo: str, page: int, token: str | None):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "limoza-vdb"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(_API.format(repo=repo, page=page), headers=headers)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def run(dirs: dict):
    dest = Path(dirs["github_repo"])
    dest.mkdir(parents=True, exist_ok=True)
    token = os.environ.get("GITHUB_TOKEN") or None
    repos = _load_repos()
    print(f"── sync github_repo ── ({len(repos)} repos, {'authed' if token else 'UNauthed 60/h'})")
    total = 0
    for repo in repos:
        advs, page = [], 1
        try:
            while True:
                batch = _fetch(repo, page, token)
                if not isinstance(batch, list) or not batch:
                    break
                advs.extend(batch)
                if len(batch) < 100:
                    break
                page += 1
        except urllib.error.HTTPError as e:
            print(f"  ✗ {repo}: HTTP {e.code} — skipped")
            continue
        (dest / (repo.replace("/", "__") + ".json")).write_text(json.dumps(advs))
        print(f"  {repo}: {len(advs)} advisories")
        total += len(advs)
    return total
