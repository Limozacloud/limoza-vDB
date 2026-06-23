"""Sync RedHat CSAF feeds from security.access.redhat.com.

Two feeds:
  vex/        (cve-*.json)  — per-CVE: severity, cvss, cwe, refs, RHSA refs, status.
                             The driver for the ingest.
  advisories/ (rhsa-*.json) — per-RHSA: title, severity, dates. Looked up to fill
                             the advisory rows that VEX references.

First run:  download the daily full archive (.tar.zst) and extract it.
Subsequent: read changes.csv, fetch only files changed since last sync.
"""
import csv
import io
import json
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

_BASE_VEX = "https://security.access.redhat.com/data/csaf/v2/vex"
_BASE_ADV = "https://security.access.redhat.com/data/csaf/v2/advisories"
_HEADERS  = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)", "Accept": "*/*"}
_RETRIES, _WAIT = 3, 5


def _get(url: str) -> bytes:
    for attempt in range(_RETRIES):
        try:
            req = urllib.request.Request(url, headers=_HEADERS)
            with urllib.request.urlopen(req, timeout=300) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404 or attempt == _RETRIES - 1:
                raise
            time.sleep(_WAIT * (attempt + 1))
        except Exception:
            if attempt == _RETRIES - 1:
                raise
            time.sleep(_WAIT * (attempt + 1))


def _full(base_url: str, dest: Path, prefix: str) -> str:
    name = _get(f"{base_url}/archive_latest.txt").decode().strip()
    print(f"    downloading {name} …")
    arc = dest / name
    arc.write_bytes(_get(f"{base_url}/{name}"))
    print("    extracting …")
    subprocess.run(["tar", "--zstd", "-xf", str(arc), "-C", str(dest)], check=True)
    arc.unlink()
    return name.removeprefix(prefix).removesuffix(".tar.zst")


def _incremental(base_url: str, dest: Path, since: str) -> int:
    since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
    reader = csv.reader(io.StringIO(_get(f"{base_url}/changes.csv").decode()))
    todo = []
    for row in reader:
        if len(row) < 2:
            continue
        try:
            if datetime.fromisoformat(row[1]).replace(tzinfo=timezone.utc) > since_dt:
                todo.append(row[0])
        except ValueError:
            continue
    saved = 0
    for p in todo:
        fp = dest / p
        fp.parent.mkdir(parents=True, exist_ok=True)
        try:
            fp.write_bytes(_get(f"{base_url}/{p}"))
            saved += 1
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
    return saved


def _feed(label, base_url, dest, prefix, state, key, today) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    last = state.get(key)
    if not last:
        print(f"  {label}: full sync")
        state[key] = _full(base_url, dest, prefix)
        return -1                                  # -1 = full sync (count unknown)
    print(f"  {label}: incremental since {last}")
    n = _incremental(base_url, dest, last)
    state[key] = today
    return n


def run(dirs: dict):
    base = Path(dirs["redhat"])
    base.mkdir(parents=True, exist_ok=True)
    ckpt = base / "checkpoint.json"
    state = json.loads(ckpt.read_bytes()) if ckpt.exists() else {}
    today = datetime.now(timezone.utc).date().isoformat()

    print("── sync redhat (vex + advisories) ──")
    nv = _feed("vex", _BASE_VEX, base / "vex", "csaf_vex_",
               state, "last_sync_vex", today)
    na = _feed("advisories", _BASE_ADV, base / "advisories", "csaf_advisories_",
               state, "last_sync_advisories", today)
    ckpt.write_bytes(json.dumps(state).encode())

    if nv == -1 or na == -1:
        print("  done (full sync)")
        return None
    total = (nv if nv > 0 else 0) + (na if na > 0 else 0)
    if not total:
        return {"status": "no_new_data", "message": "no changes in vex/advisories"}
    print(f"  fetched {total} changed files")
    return total
