"""Download FIRST EPSS scores → epss.json ({cve: [score, percentile, date]})."""
import json
import time
from pathlib import Path

from ingest.core.retry import http_get

_URL   = "https://api.first.org/data/v1/epss"
_LIMIT = 10_000


def run(dirs: dict) -> int:
    dest = Path(dirs["epss"])
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "epss.json"

    print("── sync epss ──")
    offset, idx = 0, {}
    while True:
        data = http_get(f"{_URL}?limit={_LIMIT}&offset={offset}").json()
        for row in data.get("data") or []:
            cve = row.get("cve")
            if cve:
                idx[cve] = [
                    float(row["epss"])       if row.get("epss")       else 0.0,
                    float(row["percentile"]) if row.get("percentile") else 0.0,
                    row.get("date"),
                ]
        offset += _LIMIT
        total = int(data.get("total", 0))
        print(f"  {min(offset, total):,}/{total:,}")
        if offset >= total:
            break
        time.sleep(1)

    out.write_text(json.dumps(idx, separators=(",", ":")))
    print(f"  done: {len(idx):,} scores → {out}")
    return len(idx)
