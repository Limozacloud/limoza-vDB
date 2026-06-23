"""Sync Microsoft MSRC CVRF v3.0 — one JSON document per monthly release.

Incremental by presence: existing release files are kept; the two most recent are
always re-fetched (they get revised after Patch Tuesday).
"""
import json
import urllib.request
from pathlib import Path

_BASE    = "https://api.msrc.microsoft.com/cvrf/v3.0"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)", "Accept": "application/json"}


def _get(url, timeout):
    return urllib.request.urlopen(urllib.request.Request(url, headers=_HEADERS), timeout=timeout).read()


def run(dirs: dict):
    dest = Path(dirs["microsoft"])
    dest.mkdir(parents=True, exist_ok=True)
    print("── sync microsoft (MSRC CVRF v3.0) ──")
    up = json.loads(_get(f"{_BASE}/updates", 60))
    releases = [v["ID"] for v in (up.get("value") or []) if v.get("ID")]
    # newest two by date → always refresh
    by_date = sorted((up.get("value") or []), key=lambda v: v.get("CurrentReleaseDate") or "", reverse=True)
    refresh = {v["ID"] for v in by_date[:2]}

    fetched = 0
    for rel in releases:
        fp = dest / f"{rel}.json"
        if fp.exists() and rel not in refresh:
            continue
        try:
            fp.write_bytes(_get(f"{_BASE}/cvrf/{rel}", 180))
            fetched += 1
        except Exception as e:
            print(f"  {rel}: skip ({e})")
    print(f"  microsoft: {len(releases)} releases · {fetched} fetched")
    return fetched
