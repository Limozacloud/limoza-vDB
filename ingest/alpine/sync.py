"""Sync Alpine Linux secdb from secdb.alpinelinux.org."""
import json
import urllib.request
from pathlib import Path

_BASE_URL = "https://secdb.alpinelinux.org"
_VERSIONS  = ["v3.14", "v3.15", "v3.16", "v3.17", "v3.18", "v3.19", "v3.20", "v3.21", "v3.22", "v3.23", "v3.24", "edge"]
_REPOS     = ["main", "community"]
_HEADERS   = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)"}


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers=_HEADERS)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def sync(dirs: dict) -> None:
    base = Path(dirs["alpine_secdb"])
    base.mkdir(parents=True, exist_ok=True)

    checkpoint_path = base / "checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_bytes()) if checkpoint_path.exists() else {}

    try:
        ts = _fetch(f"{_BASE_URL}/last-update").decode().strip()
    except Exception as e:
        print(f"  Alpine secdb: last-update failed: {e}")
        ts = ""

    if ts and ts == checkpoint.get("last_update"):
        print("  Alpine secdb: no changes (timestamp match), skipping")
        return

    print(f"  Alpine secdb: updating (ts={ts})...")
    downloaded = skipped = 0

    for version in _VERSIONS:
        ver_dir = base / version
        ver_dir.mkdir(exist_ok=True)
        for repo in _REPOS:
            url  = f"{_BASE_URL}/{version}/{repo}.json"
            dest = ver_dir / f"{repo}.json"
            try:
                dest.write_bytes(_fetch(url))
                downloaded += 1
            except Exception as e:
                skipped += 1
                if "404" not in str(e):
                    print(f"  Alpine secdb: {version}/{repo}: {e}")

    checkpoint_path.write_bytes(
        json.dumps({"last_update": ts}, separators=(",", ":")).encode()
    )
    print(f"  Alpine secdb: {downloaded} files downloaded, {skipped} skipped")
