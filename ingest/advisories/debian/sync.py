"""Sync the Debian security-tracker JSON (one big file, package-keyed).

DSA/DLA advisory lists live on salsa behind an anti-bot proof-of-work and aren't
fetched; the tracker JSON already carries the complete per-release fix status.
"""
import urllib.request
from pathlib import Path

_URL     = "https://security-tracker.debian.org/tracker/data/json"
_OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)"}


def run(dirs: dict):
    dest = Path(dirs["debian"])
    dest.mkdir(parents=True, exist_ok=True)
    print("── sync debian ──")
    data = urllib.request.urlopen(urllib.request.Request(_URL, headers=_HEADERS), timeout=300).read()
    (dest / "tracker.json").write_bytes(data)
    print(f"  debian tracker: {len(data) // 1024 // 1024} MB")
    osv = urllib.request.urlopen(urllib.request.Request(_OSV_URL, headers=_HEADERS), timeout=300).read()
    (dest / "osv.zip").write_bytes(osv)
    print(f"  debian osv.zip: {len(osv) // 1024 // 1024} MB (DSA/DLA advisories)")
    return len(data) + len(osv)
