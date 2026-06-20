"""NVD CPE Dictionary sync.

sync()       — downloads all ~1.7M CPEs from NVD API 2.0 → cpe_raw.json
sync_index() — parses cpe_raw.json → cpe_dict.json  (no download)

Rate limits (NVD enforces per rolling 30s window):
  Without API key: 5  req/30s → ~17 min for full download
  With    API key: 50 req/30s → ~2  min for full download

Set NVD_API_KEY in environment to use the faster limit.
Free key: https://nvd.nist.gov/developers/request-an-api-key
"""
from __future__ import annotations

from ingest import json_compat as json
import os
import time
from pathlib import Path

import httpx

_API_URL   = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
_PAGE_SIZE = 10_000
_TIMEOUT   = 60


def sync(dirs: dict) -> None:
    dest = Path(dirs["cpe"])
    dest.mkdir(parents=True, exist_ok=True)
    out_file   = dest / "cpe_raw.json"
    checkpoint = dest / "checkpoint.txt"

    api_key    = os.environ.get("NVD_API_KEY", "").strip()
    headers    = {"apiKey": api_key} if api_key else {}
    req_limit  = 50 if api_key else 5
    min_delay  = 30.0 / req_limit

    print("── sync cpe ──")
    if api_key:
        print(f"  API key: set  ({req_limit} req/30s)")
    else:
        print(f"  API key: not set — using public rate limit ({req_limit} req/30s, ~17 min)")
        print("  Tip: set NVD_API_KEY in .env to speed this up (~2 min)")

    start_index = 0
    existing: dict = {}
    if checkpoint.exists():
        try:
            start_index = int(checkpoint.read_text().strip())
            print(f"  Resuming from startIndex={start_index}")
        except ValueError:
            pass
    if start_index > 0 and out_file.exists():
        existing = json.loads(out_file.read_bytes())
        print(f"  Loaded {len(existing):,} existing entries")

    raw = existing
    last_req = 0.0

    while True:
        elapsed = time.monotonic() - last_req
        if elapsed < min_delay:
            time.sleep(min_delay - elapsed)

        params = {"resultsPerPage": _PAGE_SIZE, "startIndex": start_index}
        try:
            last_req = time.monotonic()
            resp = httpx.get(_API_URL, params=params, headers=headers, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                print("  ✗ 403 Forbidden — rate limited. Waiting 30s...")
                time.sleep(30)
                continue
            raise

        total = int(data.get("totalResults", 0))
        for item in data.get("products", []):
            cpe_obj = item.get("cpe", {})
            name_id = cpe_obj.get("cpeNameId", "")
            if name_id:
                raw[name_id] = cpe_obj

        start_index += _PAGE_SIZE
        fetched = min(start_index, total)
        print(f"  [{fetched:>9,} / {total:,}]  {fetched/total*100:.1f}%")

        checkpoint.write_text(str(start_index))
        out_file.write_bytes(json.dumps(raw, separators=(",", ":")).encode())

        if start_index >= total:
            break

    checkpoint.unlink(missing_ok=True)
    print(f"  Done. {len(raw):,} CPEs → {out_file}")
    print("  Run `sync cpe_index` to build cpe_dict.json")


def sync_index(dirs: dict) -> None:
    src = Path(dirs["cpe"]) / "cpe_raw.json"
    dst = Path(dirs["cpe"]) / "cpe_dict.json"

    if not src.exists():
        print(f"  ✗ {src} not found — run `sync cpe` first")
        return

    print("── sync cpe_index ──")
    print(f"  Reading {src} ...")
    raw: dict = json.loads(src.read_bytes())
    total = len(raw)
    print(f"  {total:,} raw CPEs to index")

    idx: dict = {}
    skipped = 0

    for name_id, cpe_obj in raw.items():
        uri        = cpe_obj.get("cpeName", "")
        deprecated = cpe_obj.get("deprecated", False)
        created    = cpe_obj.get("created")
        modified   = cpe_obj.get("lastModified")
        titles     = cpe_obj.get("titles", [])
        title_en   = next((t["title"] for t in titles if t.get("lang") == "en"), None)

        if not uri:
            skipped += 1
            continue

        parts = uri.split(":")
        if len(parts) < 6 or parts[1] != "2.3":
            skipped += 1
            continue

        cpe_type, vendor, product, version = parts[2], parts[3], parts[4], parts[5]
        if not vendor:
            skipped += 1
            continue

        idx[name_id] = [uri, cpe_type, vendor, product, version, title_en, deprecated, created, modified]

    dst.write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    print(f"  Done. {len(idx):,} CPEs indexed → {dst}")
    if skipped:
        print(f"  Skipped {skipped:,} entries (missing URI or unknown format)")
