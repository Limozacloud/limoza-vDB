"""Sync SUSE CSAF VEX files + advisory map from ftp.suse.com.

VEX (per-CVE):       csaf-vex/  — used for package fix data
Advisory (per-SUSE-SU): csaf/   — used to map CVE-IDs → SUSE-SU advisory IDs

First run:  downloads csaf-vex.tar.bz2 (~377 MB) + all ~32k advisory files.
Subsequent: reads changes.csv for each, fetches only files changed since last sync.
"""
import csv
import io
import json
import subprocess
import threading
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

_VEX_BASE_URL = "https://ftp.suse.com/pub/projects/security/csaf-vex"
_ADV_BASE_URL = "https://ftp.suse.com/pub/projects/security/csaf"
_ARCHIVE_URL  = "https://ftp.suse.com/pub/projects/security/csaf-vex.tar.bz2"
_RETRIES      = 3
_WAIT         = 5
_WORKERS      = 20
_HEADERS      = {
    "User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)",
    "Accept":     "*/*",
}


def _get(url: str) -> bytes:
    for attempt in range(_RETRIES):
        try:
            req = urllib.request.Request(url, headers=_HEADERS)
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            if attempt < _RETRIES - 1:
                time.sleep(_WAIT * (attempt + 1))
                continue
            raise
        except Exception:
            if attempt < _RETRIES - 1:
                time.sleep(_WAIT * (attempt + 1))
                continue
            raise


def _full_sync(base: Path) -> None:
    print("  SUSE: downloading csaf-vex.tar.bz2 (~377 MB)...")
    archive = base / "csaf-vex.tar.bz2"
    archive.write_bytes(_get(_ARCHIVE_URL))
    print("  SUSE: extracting...")
    subprocess.run(["tar", "-xjf", str(archive), "-C", str(base), "--strip-components=1"], check=True)
    archive.unlink()
    count = sum(1 for _ in base.glob("cve-*.json"))
    print(f"  SUSE: {count} VEX files extracted")


def _incremental_vex(base: Path, since: str) -> None:
    since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
    csv_data = _get(f"{_VEX_BASE_URL}/changes.csv").decode("utf-8")
    reader   = csv.reader(io.StringIO(csv_data))

    to_fetch: list[str] = []
    for row in reader:
        if len(row) < 2:
            continue
        fname, ts = row[0].strip(), row[1].strip()
        if not fname.endswith(".json"):
            continue
        try:
            changed = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if changed > since_dt:
            to_fetch.append(fname)

    if not to_fetch:
        print("  SUSE VEX: no changes since last sync")
        return

    print(f"  SUSE VEX: {len(to_fetch)} files changed since {since}")
    saved = errors = 0
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        futures = {pool.submit(_download_vex, base, f): f for f in to_fetch}
        for fut in as_completed(futures):
            try:
                fut.result()
                saved += 1
            except Exception as e:
                errors += 1
                if errors <= 10:
                    print(f"    Error {futures[fut]}: {e}")
    print(f"  SUSE VEX: {saved} updated, {errors} errors")


def _download_vex(base: Path, fname: str) -> None:
    (base / fname).write_bytes(_get(f"{_VEX_BASE_URL}/{fname}"))


def _sync_adv_map(base: Path, since: str | None) -> None:
    """Download SUSE advisory files and build/update {cve_id: {adv_id: [platforms]}} map."""
    adv_map_path = base / "adv_map.json"
    adv_map: dict[str, dict[str, list[str]]] = {}
    if adv_map_path.exists():
        loaded = json.loads(adv_map_path.read_bytes())
        first_val = next(iter(loaded.values()), None) if loaded else None
        if isinstance(first_val, dict):
            adv_map = loaded
        # else: old list format — start fresh (since overridden to None by caller)

    if since is None:
        print("  SUSE adv: full advisory sync — downloading index.txt...")
        index_raw = _get(f"{_ADV_BASE_URL}/index.txt").decode("utf-8")
        fnames = [l.strip() for l in index_raw.splitlines()
                  if l.strip().endswith(".json")]
        print(f"  SUSE adv: {len(fnames)} advisory files to process")
    else:
        since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
        csv_raw  = _get(f"{_ADV_BASE_URL}/changes.csv").decode("utf-8")
        reader   = csv.reader(io.StringIO(csv_raw))
        fnames   = []
        for row in reader:
            if len(row) < 2:
                continue
            fname, ts = row[0].strip(), row[1].strip()
            if not fname.endswith(".json"):
                continue
            try:
                changed = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if changed > since_dt:
                fnames.append(fname)
        if not fnames:
            print("  SUSE adv: no advisory changes since last sync")
            return
        print(f"  SUSE adv: {len(fnames)} advisories changed since {since}")

    adv_dir = base / "advisories"
    adv_dir.mkdir(exist_ok=True)

    lock      = threading.Lock()
    processed = 0
    errors    = 0

    def _process(fname: str) -> None:
        nonlocal processed, errors
        try:
            raw    = _get(f"{_ADV_BASE_URL}/{fname}")
            data   = json.loads(raw)
            adv_id = (data.get("document") or {}).get("tracking", {}).get("id", "")
            if not adv_id:
                return
            (adv_dir / fname).write_bytes(raw)
            # Build {cve_id: {platforms}} from product_status.recommended
            cve_platforms: dict[str, set] = {}
            for vuln in (data.get("vulnerabilities") or []):
                cve = (vuln.get("cve") or "").strip()
                if not cve.startswith("CVE-"):
                    continue
                ps = vuln.get("product_status", {})
                platforms: set[str] = set()
                for pid in (ps.get("recommended") or []) + (ps.get("fixed") or []):
                    colon = pid.find(":")
                    if colon > 0:
                        platforms.add(pid[:colon])
                cve_platforms[cve] = platforms
            if not cve_platforms:
                return
            with lock:
                for cve, platforms in cve_platforms.items():
                    cve_entry = adv_map.setdefault(cve, {})
                    existing  = set(cve_entry.get(adv_id, []))
                    cve_entry[adv_id] = sorted(existing | platforms)
                processed += 1
                if processed % 2000 == 0:
                    print(f"  SUSE adv: {processed}/{len(fnames)} processed...")
        except Exception as e:
            with lock:
                errors += 1
            if errors <= 10:
                print(f"    SUSE adv error {fname}: {e}")

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        list(as_completed([pool.submit(_process, f) for f in fnames]))

    adv_map_path.write_bytes(json.dumps(adv_map, separators=(",", ":")).encode())
    print(f"  SUSE adv: {processed} advisories processed, {errors} errors → "
          f"{len(adv_map)} CVEs in map")


def sync(dirs: dict) -> None:
    base = Path(dirs["suse_vex"])
    base.mkdir(parents=True, exist_ok=True)

    checkpoint_path = base / "checkpoint.json"
    checkpoint: dict = {}
    if checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_bytes())

    last_vex = checkpoint.get("last_vex_sync")
    last_adv = checkpoint.get("last_adv_sync")

    # Detect old list-format adv_map and force full advisory resync
    adv_map_path = base / "adv_map.json"
    if adv_map_path.exists() and last_adv is not None:
        sample = json.loads(adv_map_path.read_bytes())
        first_val = next(iter(sample.values()), None) if sample else None
        if isinstance(first_val, list):
            print("  SUSE adv: format migration detected — forcing full advisory resync")
            last_adv = None

    # Force full advisory resync if advisories/ dir is missing or empty
    adv_dir = base / "advisories"
    if last_adv is not None and (not adv_dir.exists() or not any(adv_dir.iterdir())):
        print("  SUSE adv: advisories/ dir empty — forcing full advisory resync")
        last_adv = None

    # ── VEX sync ─────────────────────────────────────────────────────────────
    if last_vex is None:
        print("  SUSE: first run — full VEX sync")
        _full_sync(base)
    else:
        print(f"  SUSE: incremental VEX sync since {last_vex}")
        _incremental_vex(base, last_vex)

    # ── Advisory map sync ─────────────────────────────────────────────────────
    if last_adv is None:
        print("  SUSE: first run — full advisory map sync")
    else:
        print(f"  SUSE: incremental advisory map sync since {last_adv}")
    _sync_adv_map(base, last_adv)

    now = datetime.now(timezone.utc).isoformat()
    checkpoint_path.write_bytes(
        json.dumps({"last_vex_sync": now, "last_adv_sync": now},
                   separators=(",", ":")).encode()
    )
    print(f"  SUSE: checkpoint updated: {now}")
