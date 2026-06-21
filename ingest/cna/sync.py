"""Download the CNA list (CVEProject/cve-website CNAsList.json)."""
import json
from pathlib import Path

from ingest.retry import http_get

_URL = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"


def run(dirs: dict) -> int:
    dest = Path(dirs["cna"])
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "cnas.json"

    print("── sync cna ──")
    data = http_get(_URL).json()
    out.write_text(json.dumps(data, separators=(",", ":")))
    print(f"  done: {len(data):,} CNAs → {out}")
    return len(data)
