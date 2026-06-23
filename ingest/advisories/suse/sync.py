"""Sync SUSE CSAF feeds from ftp.suse.com.

  csaf-vex/  (cve-*.json)    — per-CVE VEX, fetched as one tar.bz2 archive (~377 MB).
  csaf/      (*-su-*.json)   — per-advisory; only security updates (-su-), listed in
                              index.txt, downloaded individually (no archive).

First run: full. Subsequent: each feed's changes.csv → only changed files.
"""
import csv
import io
import json
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

_VEX_BASE   = "https://ftp.suse.com/pub/projects/security/csaf-vex"
_ADV_BASE   = "https://ftp.suse.com/pub/projects/security/csaf"
_VEX_ARCHIVE = "https://ftp.suse.com/pub/projects/security/csaf-vex.tar.bz2"
_HEADERS    = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)", "Accept": "*/*"}
_RETRIES, _WAIT = 3, 5


def _get(url: str) -> bytes:
    for attempt in range(_RETRIES):
        try:
            req = urllib.request.Request(url, headers=_HEADERS)
            with urllib.request.urlopen(req, timeout=600) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404 or attempt == _RETRIES - 1:
                raise
            time.sleep(_WAIT * (attempt + 1))
        except Exception:
            if attempt == _RETRIES - 1:
                raise
            time.sleep(_WAIT * (attempt + 1))


def _changed(base_url: str, since: str) -> list:
    since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
    reader = csv.reader(io.StringIO(_get(f"{base_url}/changes.csv").decode()))
    out = []
    for row in reader:
        if len(row) < 2 or not row[0].strip().endswith(".json"):
            continue
        try:
            if datetime.fromisoformat(row[1].strip()).replace(tzinfo=timezone.utc) > since_dt:
                out.append(row[0].strip())
        except ValueError:
            continue
    return out


def _fetch_many(base_url: str, dest: Path, names: list) -> int:
    saved = 0
    def _one(fn):
        try:
            (dest / fn).write_bytes(_get(f"{base_url}/{fn}"))
            return 1
        except Exception:
            return 0
    with ThreadPoolExecutor(max_workers=16) as pool:
        for r in pool.map(_one, names):
            saved += r
    return saved


def _sync_vex(base: Path, since) -> int:
    dest = base / "vex"
    dest.mkdir(parents=True, exist_ok=True)
    if not since:
        print("  vex: downloading csaf-vex.tar.bz2 (~377 MB) …")
        arc = base / "csaf-vex.tar.bz2"
        arc.write_bytes(_get(_VEX_ARCHIVE))
        print("    extracting …")
        subprocess.run(["tar", "-xjf", str(arc), "-C", str(dest), "--strip-components=1"], check=True)
        arc.unlink()
        return -1
    names = _changed(_VEX_BASE, since)
    if not names:
        return 0
    print(f"  vex: {len(names)} changed")
    return _fetch_many(_VEX_BASE, dest, names)


def _sync_adv(base: Path, since) -> int:
    dest = base / "advisories"
    dest.mkdir(parents=True, exist_ok=True)
    if not since:
        names = [l.strip() for l in _get(f"{_ADV_BASE}/index.txt").decode().splitlines()
                 if l.strip().endswith(".json") and "-su-" in l.lower()]
        print(f"  advisories: full — {len(names):,} security updates")
    else:
        names = [n for n in _changed(_ADV_BASE, since) if "-su-" in n.lower()]
        if not names:
            return 0
        print(f"  advisories: {len(names)} changed")
    return _fetch_many(_ADV_BASE, dest, names)


def run(dirs: dict):
    base = Path(dirs["suse"])
    base.mkdir(parents=True, exist_ok=True)
    ckpt = base / "checkpoint.json"
    state = json.loads(ckpt.read_bytes()) if ckpt.exists() else {}
    today = datetime.now(timezone.utc).date().isoformat()

    print("── sync suse (vex + advisories) ──")
    nv = _sync_vex(base, state.get("last_vex"))
    state["last_vex"] = today if nv != -1 else today
    na = _sync_adv(base, state.get("last_adv"))
    state["last_adv"] = today
    ckpt.write_bytes(json.dumps(state).encode())

    if nv == -1:
        print("  done (full sync)")
        return None
    total = (nv if nv > 0 else 0) + (na if na > 0 else 0)
    if not total:
        return {"status": "no_new_data", "message": "no changes in vex/advisories"}
    print(f"  fetched {total} changed files")
    return total
