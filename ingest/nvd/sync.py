"""Sync NVD CVE data directly from NVD API 2.0.

Saves one JSON file per CVE to {nvd_dir}/api/{year}/{CVE-ID}.json —
same structure the transform expects.

Incremental: stores last sync timestamp in {nvd_dir}/last_modified.txt.
On first run does a full download (~300k CVEs).

Rate limits (sliding 30-second window):
  Without key: 5 req / 30s  →  ~150 pages = ~15 min
  With key:    50 req / 30s →  ~150 pages = ~90 sec

Set NVD_API_KEY env var to use the higher limit.
"""
import json
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import httpx

_API_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE  = 2000
_WINDOW     = 30.0  # seconds


class _RateLimiter:
    """Sliding-window rate limiter. Allows up to `limit` calls in any `window`-second window."""

    def __init__(self, limit: int, window: float):
        self._limit  = limit
        self._window = window
        self._calls: deque[float] = deque()

    def wait(self) -> None:
        now = time.monotonic()
        # Drop calls outside the window
        while self._calls and now - self._calls[0] >= self._window:
            self._calls.popleft()
        if len(self._calls) >= self._limit:
            # Sleep until the oldest call slides out
            sleep_for = self._window - (now - self._calls[0]) + 0.05
            time.sleep(sleep_for)
        self._calls.append(time.monotonic())


def sync(dirs: dict) -> None:
    dest = Path(dirs["nvd"]) / "api"
    dest.mkdir(parents=True, exist_ok=True)

    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    limiter = _RateLimiter(limit=50 if api_key else 5, window=_WINDOW)

    if api_key:
        print("── sync nvd (API key: 50 req/30s) ──")
    else:
        print("── sync nvd (no API key: 5 req/30s — set NVD_API_KEY for 10x speed) ──")

    ts_file       = Path(dirs["nvd"]) / "last_modified.txt"
    last_modified = ts_file.read_text().strip() if ts_file.exists() else None
    now_str       = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

    params: dict = {"resultsPerPage": _PAGE_SIZE, "startIndex": 0}
    if last_modified:
        params["lastModStartDate"] = last_modified
        params["lastModEndDate"]   = now_str
        print(f"  Incremental since {last_modified}")
    else:
        print("  Full sync")

    total_saved = 0

    while True:
        limiter.wait()

        # Retry loop with exponential backoff
        resp = None
        for attempt in range(5):
            try:
                resp = httpx.get(_API_URL, params=params, headers=headers, timeout=60)
                if resp.status_code in (403, 429):
                    wait = 30 * (attempt + 1)
                    print(f"  Rate limited (attempt {attempt+1}), sleeping {wait}s...")
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                break
            except httpx.HTTPStatusError:
                if attempt == 4:
                    raise
                time.sleep(10 * (attempt + 1))

        data          = resp.json()
        total_results = data.get("totalResults", 0)
        vulns         = data.get("vulnerabilities") or []

        for item in vulns:
            cve    = item.get("cve") or {}
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            year    = cve_id.split("-")[1]
            out_dir = dest / year
            out_dir.mkdir(exist_ok=True)
            (out_dir / f"{cve_id}.json").write_bytes(
                json.dumps(cve, separators=(",", ":")).encode()
            )
            total_saved += 1

        start_index = params["startIndex"] + len(vulns)
        print(f"  {min(start_index, total_results)}/{total_results}  ({total_saved} saved)")

        if start_index >= total_results:
            break

        params["startIndex"] = start_index

    ts_file.write_text(now_str)
    print(f"  Done. {total_saved} CVEs → {dest}")
