import json
import time
from pathlib import Path

import httpx


def sync(dirs: dict) -> None:
    dest = Path(dirs["epss"])
    dest.mkdir(parents=True, exist_ok=True)
    out  = dest / "epss.json"

    print("── sync epss ──")
    limit  = 10_000
    offset = 0
    idx: dict[str, list] = {}

    while True:
        url  = f"https://api.first.org/data/v1/epss?limit={limit}&offset={offset}"
        resp = httpx.get(url, timeout=60, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        for row in (data.get("data") or []):
            cve = row.get("cve")
            if cve:
                idx[cve] = [
                    float(row["epss"])       if row.get("epss")       else 0.0,
                    float(row["percentile"]) if row.get("percentile") else 0.0,
                    row.get("date"),
                ]
        offset += limit
        total   = int(data.get("total", 0))
        print(f"  {min(offset, total)}/{total}")
        if offset >= total:
            break
        time.sleep(1)

    out.write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    print(f"  Done. {len(idx)} scores → {out}")
