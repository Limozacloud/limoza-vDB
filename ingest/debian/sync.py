"""Sync Debian Security Tracker JSON + DSA/DLA advisory lists."""
from ingest import json_compat as json
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

_URL      = "https://security-tracker.debian.org/tracker/data/json"
_GIT_REPO = "https://salsa.debian.org/security-tracker-team/security-tracker.git"
_HEADERS  = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)"}
_RETRIES  = 3


def _fetch_adv_lists(dest_dir: Path) -> None:
    """Clone only data/DSA/list + data/DLA/list via git sparse-checkout."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([
            "git", "clone", "--depth=1", "--no-checkout", "--filter=blob:none",
            _GIT_REPO, tmp,
        ], check=True, capture_output=True)
        subprocess.run(
            ["git", "sparse-checkout", "set", "data/DSA/list", "data/DLA/list"],
            check=True, capture_output=True, cwd=tmp,
        )
        subprocess.run(
            ["git", "checkout"],
            check=True, capture_output=True, cwd=tmp,
        )
        for src, dst in [
            ("data/DSA/list", "dsa_list.txt"),
            ("data/DLA/list", "dla_list.txt"),
        ]:
            src_path = Path(tmp) / src
            if src_path.exists():
                (dest_dir / dst).write_bytes(src_path.read_bytes())


def _head(url: str) -> dict:
    req = urllib.request.Request(url, headers=_HEADERS, method="HEAD")
    with urllib.request.urlopen(req, timeout=30) as r:
        return {
            "etag":          r.headers.get("ETag", ""),
            "last_modified": r.headers.get("Last-Modified", ""),
        }


def _download(url: str, dest: Path) -> None:
    for attempt in range(_RETRIES):
        try:
            req = urllib.request.Request(url, headers=_HEADERS)
            with urllib.request.urlopen(req, timeout=600) as r:
                dest.write_bytes(r.read())
            return
        except Exception:
            if attempt < _RETRIES - 1:
                time.sleep(5 * (attempt + 1))
                continue
            raise


def sync(dirs: dict) -> None:
    base = Path(dirs["debian_tracker"])
    base.mkdir(parents=True, exist_ok=True)

    checkpoint_path = base / "checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_bytes()) if checkpoint_path.exists() else {}

    try:
        meta = _head(_URL)
    except Exception as e:
        print(f"  Debian tracker: HEAD failed: {e}")
        meta = {}

    if meta.get("etag") and meta["etag"] == checkpoint.get("etag"):
        print("  Debian tracker: no changes (ETag match), skipping download")
        return

    data_path = base / "data.json"
    print("  Debian tracker: downloading data.json (~75MB)...")
    _download(_URL, data_path)

    size_mb = data_path.stat().st_size / 1_048_576
    print(f"  Debian tracker: {size_mb:.1f} MB downloaded")

    # Fetch DSA/DLA lists via git sparse-checkout (bypasses Salsa PoW)
    print("  Debian tracker: fetching DSA/DLA lists via git...")
    _fetch_adv_lists(base)
    print("  Debian tracker: DSA/DLA lists updated")

    checkpoint_path.write_bytes(
        json.dumps({
            "etag":          meta.get("etag", ""),
            "last_modified": meta.get("last_modified", ""),
        }, separators=(",", ":")).encode()
    )
    print(f"  Debian tracker: done (etag={meta.get('etag', 'n/a')})")
