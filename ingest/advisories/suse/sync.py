"""Sync SUSE CSAF feeds from ftp.suse.com.

  csaf-vex/  (<year>/cve-*.json) — per-CVE VEX, fetched as one tar.bz2 archive (~377 MB). SUSE moved the
                              files into year sub-directories; copies synced before that stay flat in vex/.
  csaf/      (*-su-*.json)   — per-advisory; only security updates (-su-), listed in
                              index.txt, downloaded individually (no archive).

First run: full. Subsequent: each feed's changes.csv → only changed files. VEX files are compared with
the local copy's timestamp (not with a "since" date), so a file whose download failed in an earlier run
is fetched again by the next one; the advisory checkpoint only advances when every download worked.
"""
import csv
import io
import json
import os
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


def _stale(base_url: str, dest: Path, tolerance: float = 2.0) -> list:
    """Files listed in the feed's changes.csv whose local copy is missing or older than SUSE's change
    time. A copy counts at its year path and at the flat path older syncs used. Unlike a "since" date this
    does not depend on what earlier runs managed to download."""
    reader = csv.reader(io.StringIO(_get(f"{base_url}/changes.csv").decode()))
    out = []
    for row in reader:
        if len(row) < 2 or not row[0].strip().endswith(".json"):
            continue
        name = row[0].strip()
        try:
            changed = datetime.fromisoformat(row[1].strip().replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        local = 0.0
        for cand in (dest / name, dest / Path(name).name):
            try:
                local = max(local, os.stat(cand).st_mtime)
            except OSError:
                pass
        if local + tolerance < changed:
            out.append(name)
    return out


def _fetch_many(base_url: str, dest: Path, names: list) -> tuple:
    """Download names (they carry SUSE's year sub-directory, e.g. "2026/cve-2026-1234.json").
    Returns (downloaded, failed names)."""
    def _one(fn):
        try:
            out = dest / fn
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(_get(f"{base_url}/{fn}"))
            return None
        except Exception as e:
            return (fn, str(e))
    with ThreadPoolExecutor(max_workers=16) as pool:
        failed = [r for r in pool.map(_one, names) if r]
    if failed:
        print(f"  WARNING: {len(failed)}/{len(names)} downloads failed, e.g. {failed[:3]}")
    return len(names) - len(failed), [f[0] for f in failed]


def vex_files(vex_dir: Path) -> list:
    """One VEX file per CVE. A CVE can have an old flat copy and a newer year-directory copy: the newest wins."""
    best = {}
    for f in vex_dir.rglob("cve-*.json"):
        if f.name not in best or f.stat().st_mtime > best[f.name].stat().st_mtime:
            best[f.name] = f
    return sorted(best.values())


def _sync_vex(base: Path, since) -> tuple:
    """Returns (downloaded, failed names); downloaded is -1 after a full archive sync."""
    dest = base / "vex"
    dest.mkdir(parents=True, exist_ok=True)
    if not since:
        print("  vex: downloading csaf-vex.tar.bz2 (~377 MB) …")
        arc = base / "csaf-vex.tar.bz2"
        arc.write_bytes(_get(_VEX_ARCHIVE))
        print("    extracting …")
        subprocess.run(["tar", "-xjf", str(arc), "-C", str(dest), "--strip-components=1"], check=True)
        arc.unlink()
        return -1, []
    names = _stale(_VEX_BASE, dest)
    if not names:
        return 0, []
    print(f"  vex: {len(names)} changed or missing locally")
    return _fetch_many(_VEX_BASE, dest, names)


def _sync_adv(base: Path, since) -> tuple:
    """Returns (downloaded, failed names)."""
    dest = base / "advisories"
    dest.mkdir(parents=True, exist_ok=True)
    if not since:
        names = [l.strip() for l in _get(f"{_ADV_BASE}/index.txt").decode().splitlines()
                 if l.strip().endswith(".json") and "-su-" in l.lower()]
        print(f"  advisories: full — {len(names):,} security updates")
    else:
        names = [n for n in _changed(_ADV_BASE, since) if "-su-" in n.lower()]
        if not names:
            return 0, []
        print(f"  advisories: {len(names)} changed")
    return _fetch_many(_ADV_BASE, dest, names)


def run(dirs: dict):
    base = Path(dirs["suse"])
    base.mkdir(parents=True, exist_ok=True)
    ckpt = base / "checkpoint.json"
    state = json.loads(ckpt.read_bytes()) if ckpt.exists() else {}
    today = datetime.now(timezone.utc).date().isoformat()

    print("── sync suse (vex + advisories) ──")
    nv, vex_failed = _sync_vex(base, state.get("last_vex"))
    state["last_vex"] = today                 # VEX is compared per file, a failed download is retried next run
    na, adv_failed = _sync_adv(base, state.get("last_adv"))
    if not adv_failed:                        # keep the old date so the failed advisories are asked for again
        state["last_adv"] = today
    ckpt.write_bytes(json.dumps(state).encode())
    if vex_failed or adv_failed:
        print(f"  WARNING: {len(vex_failed)} vex and {len(adv_failed)} advisory downloads failed; retried next run")

    if nv == -1:
        print("  done (full sync)")
        return None
    total = (nv if nv > 0 else 0) + (na if na > 0 else 0)
    if not total:
        return {"status": "no_new_data", "message": "no changes in vex/advisories"}
    print(f"  fetched {total} changed files")
    return total
