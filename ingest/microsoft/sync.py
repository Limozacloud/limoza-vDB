"""Download MSRC CVRF monthly bulletins to {msrc_dir}/cvrf/."""
import json
import time
from pathlib import Path

import httpx

_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v2.0/updates"
_CVRF_URL    = "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{release}"
_HEADERS     = {"Accept": "application/json"}
_RETRY_SLEEP = 5


def sync(dirs: dict, since: int | None = None) -> None:
    out_dir = Path(dirs["msrc"]) / "cvrf"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("── sync microsoft ──")
    print("  Fetching MSRC update list...")
    r = httpx.get(_UPDATES_URL, headers=_HEADERS, timeout=30)
    r.raise_for_status()
    releases = [entry["ID"] for entry in r.json().get("value", [])]
    print(f"  {len(releases)} releases available")

    if since:
        releases = [rel for rel in releases if int(rel.split("-")[0]) >= since]
        print(f"  {len(releases)} releases from {since} onwards")

    downloaded = skipped = errors = 0
    for release in releases:
        out = out_dir / f"{release}.json"
        if out.exists():
            skipped += 1
            continue
        try:
            resp = httpx.get(_CVRF_URL.format(release=release), headers=_HEADERS, timeout=60)
            resp.raise_for_status()
            out.write_bytes(json.dumps(resp.json(), separators=(",", ":")).encode())
            downloaded += 1
            print(f"  {release} ✓")
        except Exception as e:
            errors += 1
            print(f"  {release} ERROR: {e}")
            time.sleep(_RETRY_SLEEP)

    print(f"  Done: {downloaded} downloaded, {skipped} skipped, {errors} errors")
