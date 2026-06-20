"""Sync Oracle Linux OVAL from linux.oracle.com."""
import bz2
from ingest import json_compat as json
import time
import urllib.request
from pathlib import Path

_URL = "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)"}
_RETRIES = 3


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
    base = Path(dirs["oracle_oval"])
    base.mkdir(parents=True, exist_ok=True)

    checkpoint_path = base / "checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_bytes()) if checkpoint_path.exists() else {}

    try:
        meta = _head(_URL)
    except Exception as e:
        print(f"  Oracle OVAL: HEAD failed: {e}")
        meta = {}

    if meta.get("etag") and meta["etag"] == checkpoint.get("etag"):
        print("  Oracle OVAL: no changes (ETag match), skipping download")
        return

    bz2_path = base / "com.oracle.elsa-all.xml.bz2"
    print("  Oracle OVAL: downloading com.oracle.elsa-all.xml.bz2...")
    _download(_URL, bz2_path)

    xml_path = base / "com.oracle.elsa-all.xml"
    print("  Oracle OVAL: decompressing...")
    with bz2.open(str(bz2_path), "rb") as f_in:
        xml_path.write_bytes(f_in.read())
    bz2_path.unlink()

    checkpoint_path.write_bytes(
        json.dumps({
            "etag":          meta.get("etag", ""),
            "last_modified": meta.get("last_modified", ""),
        }, separators=(",", ":")).encode()
    )
    print(f"  Oracle OVAL: done (etag={meta.get('etag', 'n/a')})")
