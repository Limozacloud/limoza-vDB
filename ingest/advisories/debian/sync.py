"""Sync the Debian security-tracker JSON (one big file, package-keyed).

DSA/DLA advisory lists live on salsa behind an anti-bot proof-of-work and aren't
fetched; the tracker JSON already carries the complete per-release fix status.
"""
import urllib.request
from pathlib import Path

_URL     = "https://security-tracker.debian.org/tracker/data/json"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)"}


def run(dirs: dict):
    dest = Path(dirs["debian"])
    dest.mkdir(parents=True, exist_ok=True)
    print("── sync debian ──")
    req = urllib.request.Request(_URL, headers=_HEADERS)
    data = urllib.request.urlopen(req, timeout=300).read()
    (dest / "tracker.json").write_bytes(data)
    print(f"  debian: {len(data) // 1024 // 1024} MB")
    return len(data)
