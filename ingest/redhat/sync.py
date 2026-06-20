"""Sync RedHat CSAF files from security.access.redhat.com.

Two feeds, same pattern (archive + changes.csv):
  VEX:       /data/csaf/v2/vex        → base/vex/{year}/cve-*.json
  Advisories:/data/csaf/v2/advisories → base/advisories/{year}/rhsa-*.json

First run:  downloads daily full archive (.tar.zst) and extracts it.
Subsequent: reads changes.csv and fetches only files changed since last sync.
"""
import csv
import io
from ingest import json_compat as json
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

_BASE_VEX  = "https://security.access.redhat.com/data/csaf/v2/vex"
_BASE_ADV  = "https://security.access.redhat.com/data/csaf/v2/advisories"
_RETRIES   = 3
_WAIT      = 5
_HEADERS   = {
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


def _full_sync(base_url: str, dest: Path, archive_prefix: str) -> str:
    """Download and extract the full archive. Returns the archive date string."""
    archive_name = _get(f"{base_url}/archive_latest.txt").decode().strip()
    print(f"    Downloading {archive_name}...")

    archive_path = dest / archive_name
    data = _get(f"{base_url}/{archive_name}")
    archive_path.write_bytes(data)
    print(f"    Downloaded {len(data) // 1024 // 1024} MB — extracting...")

    subprocess.run(
        ["tar", "--zstd", "-xf", str(archive_path), "-C", str(dest)],
        check=True,
    )
    archive_path.unlink()

    date_str = archive_name.removeprefix(archive_prefix).removesuffix(".tar.zst")
    print(f"    Extracted — {date_str}")
    return date_str


def _incremental_sync(base_url: str, dest: Path, since: str) -> int:
    """Download files listed in changes.csv newer than `since`. Returns count."""
    since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)

    csv_data = _get(f"{base_url}/changes.csv").decode("utf-8")
    reader   = csv.reader(io.StringIO(csv_data))

    to_fetch: list[str] = []
    for row in reader:
        if len(row) < 2:
            continue
        path, ts = row[0], row[1]
        try:
            changed = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if changed > since_dt:
            to_fetch.append(path)

    if not to_fetch:
        print(f"    No changes since {since}")
        return 0

    print(f"    {len(to_fetch)} files changed since {since}")
    saved = errors = 0
    for path in to_fetch:
        file_dest = dest / path
        file_dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            file_dest.write_bytes(_get(f"{base_url}/{path}"))
            saved += 1
        except urllib.error.HTTPError as e:
            if e.code != 404:
                errors += 1
                if errors <= 5:
                    print(f"      HTTP {e.code}: {path}")
        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"      Error {path}: {e}")

    print(f"    Updated {saved} files, {errors} errors")
    return saved


def _sync_feed(label: str, base_url: str, dest: Path, archive_prefix: str,
               checkpoint: dict, checkpoint_key: str) -> str:
    """Sync one feed. Returns today's date string for checkpoint update."""
    dest.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc).date().isoformat()

    last_sync = checkpoint.get(checkpoint_key)
    if not last_sync:
        print(f"  RedHat {label}: full sync")
        date_str = _full_sync(base_url, dest, archive_prefix)
        return date_str
    else:
        print(f"  RedHat {label}: incremental since {last_sync}")
        _incremental_sync(base_url, dest, last_sync)
        return today


def sync(dirs: dict) -> None:
    base             = Path(dirs["redhat"])
    base.mkdir(parents=True, exist_ok=True)
    checkpoint_path  = base / "checkpoint.json"

    checkpoint: dict = {}
    if checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_bytes())
        # migrate old single-key checkpoint
        if "last_sync" in checkpoint and "last_sync_vex" not in checkpoint:
            checkpoint["last_sync_vex"] = checkpoint.pop("last_sync")

    vex_date = _sync_feed(
        label            = "VEX",
        base_url         = _BASE_VEX,
        dest             = base / "vex",
        archive_prefix   = "csaf_vex_",
        checkpoint       = checkpoint,
        checkpoint_key   = "last_sync_vex",
    )
    checkpoint["last_sync_vex"] = vex_date

    adv_date = _sync_feed(
        label            = "advisories",
        base_url         = _BASE_ADV,
        dest             = base / "advisories",
        archive_prefix   = "csaf_advisories_",
        checkpoint       = checkpoint,
        checkpoint_key   = "last_sync_advisories",
    )
    checkpoint["last_sync_advisories"] = adv_date

    checkpoint_path.write_bytes(
        json.dumps(checkpoint, separators=(",", ":")).encode()
    )
    print(f"  Checkpoint updated: vex={vex_date} advisories={adv_date}")
