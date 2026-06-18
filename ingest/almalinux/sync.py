"""Sync AlmaLinux errata from errata.almalinux.org."""
import json
import urllib.request
from pathlib import Path

_VERSIONS = ["8", "9", "10"]
_BASE_URL = "https://errata.almalinux.org"
_HEADERS  = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)"}


def _head(url: str) -> dict:
    req = urllib.request.Request(url, headers=_HEADERS, method="HEAD")
    with urllib.request.urlopen(req, timeout=30) as r:
        return {"etag": r.headers.get("ETag", ""), "lm": r.headers.get("Last-Modified", "")}


def sync(dirs: dict) -> None:
    base = Path(dirs["almalinux_errata"])
    base.mkdir(parents=True, exist_ok=True)

    checkpoint_path = base / "checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_bytes()) if checkpoint_path.exists() else {}

    downloaded = 0
    new_ck: dict = {}

    for version in _VERSIONS:
        url  = f"{_BASE_URL}/{version}/errata.json"
        dest = base / f"{version}.json"

        try:
            meta = _head(url)
        except Exception as e:
            print(f"  AlmaLinux {version}: HEAD failed: {e}")
            new_ck[version] = checkpoint.get(version, {})
            continue

        ck = checkpoint.get(version, {})
        new_ck[version] = meta

        if meta["etag"] and meta["etag"] == ck.get("etag"):
            continue
        if not meta["etag"] and meta["lm"] and meta["lm"] == ck.get("lm"):
            continue

        print(f"  AlmaLinux: downloading {version}/errata.json ...")
        req = urllib.request.Request(url, headers=_HEADERS)
        with urllib.request.urlopen(req, timeout=300) as r:
            dest.write_bytes(r.read())
        downloaded += 1

    checkpoint_path.write_bytes(json.dumps(new_ck, separators=(",", ":")).encode())
    if downloaded:
        print(f"  AlmaLinux: {downloaded} file(s) updated")
    else:
        print("  AlmaLinux: no changes")
