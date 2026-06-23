"""Sync Rocky Linux advisories — paginate the resf Apollo API into one JSON file."""
import json
import urllib.request
from pathlib import Path

_BASE    = "https://apollo.build.resf.org/api/v3/advisories"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)", "Accept": "application/json"}
_SIZE    = 100


def run(dirs: dict):
    dest = Path(dirs["rocky"])
    dest.mkdir(parents=True, exist_ok=True)
    print("── sync rocky (apollo) ──")
    out = []
    page = 1
    while True:
        req = urllib.request.Request(f"{_BASE}?page={page}&size={_SIZE}", headers=_HEADERS)
        d = json.loads(urllib.request.urlopen(req, timeout=120).read())
        advs = d.get("advisories") or []
        out.extend(advs)
        total = d.get("total", 0)
        if not advs or len(out) >= total:
            break
        page += 1
    (dest / "advisories.json").write_bytes(json.dumps(out).encode())
    print(f"  rocky: {len(out):,} advisories")
    return len(out)
