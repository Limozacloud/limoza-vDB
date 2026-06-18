"""Sync BSI WID CSAF advisories.

Index:  Downloads the ROLIE feed (bsi-wid-white.json) and extracts
        CVE→WID mappings into bsi_index.json.

CSAF:   Downloads individual CSAF files from changes.csv, caching them
        under csaf/{year}/{wid_id}.json.  Uses a manifest (csaf_manifest.json)
        keyed by relative path → last_modified timestamp for incremental sync.
"""
import csv
import io
import json
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_BASE_URL    = "https://wid.cert-bund.de/.well-known/csaf/white"
_ROLIE_URL   = f"{_BASE_URL}/bsi-wid-white.json"
_CHANGES_URL = f"{_BASE_URL}/changes.csv"
_HEADERS     = {"User-Agent": "Mozilla/5.0 CVE-Pipeline/1.0"}
_WORKERS     = 10
_RETRIES     = 3


def _get(url: str, timeout: int = 30) -> bytes:
    for attempt in range(_RETRIES):
        try:
            req = urllib.request.Request(url, headers=_HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception:
            if attempt < _RETRIES - 1:
                time.sleep(2 ** attempt)
                continue
            raise


def _sync_index(dest: Path) -> dict:
    """Download ROLIE feed → build CVE→{wid_id, wid_url} index."""
    print("  BSI: downloading ROLIE feed...")
    data = json.loads(_get(_ROLIE_URL, timeout=120))

    idx: dict[str, dict] = {}
    for entry in (data.get("feed", {}).get("entry", []) or []):
        wid_id  = entry.get("id", "")
        wid_url = (entry.get("content") or {}).get("src", "")
        for cat in (entry.get("category") or []):
            if cat.get("scheme", "").startswith("https://www.cve.org"):
                cve_id = cat.get("term", "")
                if cve_id and cve_id not in idx:
                    idx[cve_id] = {"wid_id": wid_id, "wid_url": wid_url}

    (dest / "bsi_index.json").write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    print(f"  BSI: {len(idx)} CVEs indexed")
    return idx


def _sync_csaf(dest: Path) -> None:
    """Download new/changed CSAF files from changes.csv."""
    csaf_dir = dest / "csaf"
    csaf_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = dest / "csaf_manifest.json"
    manifest: dict[str, str] = json.loads(manifest_path.read_bytes()) if manifest_path.exists() else {}

    print("  BSI: fetching changes.csv...")
    raw = _get(_CHANGES_URL).decode("utf-8")

    # changes.csv format: "2026/wid-sec-w-2026-1930.json","2026-06-15T22:00:00+0000"
    reader = csv.reader(io.StringIO(raw))
    all_entries = [(row[0], row[1]) for row in reader if len(row) >= 2]

    to_download = [
        (path, ts) for path, ts in all_entries
        if manifest.get(path) != ts
    ]

    print(f"  BSI: {len(all_entries)} CSAF files total, {len(to_download)} new/changed")
    if not to_download:
        return

    downloaded = 0
    errors     = 0

    def _fetch(path: str, ts: str):
        url      = f"{_BASE_URL}/{path}"
        out_path = csaf_dir / path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        data = _get(url)
        out_path.write_bytes(data)
        return path, ts

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        futures = {pool.submit(_fetch, p, ts): (p, ts) for p, ts in to_download}
        for future in as_completed(futures):
            try:
                path, ts = future.result()
                manifest[path] = ts
                downloaded += 1
                if downloaded % 500 == 0:
                    print(f"  BSI: {downloaded}/{len(to_download)} downloaded")
                    manifest_path.write_bytes(json.dumps(manifest, separators=(",", ":")).encode())
            except Exception as e:
                errors += 1
                if errors <= 5:
                    orig_path = futures[future][0]
                    print(f"  BSI: error {orig_path}: {e}")

    manifest_path.write_bytes(json.dumps(manifest, separators=(",", ":")).encode())
    print(f"  BSI: {downloaded} downloaded, {errors} errors")


def sync(dirs: dict) -> None:
    dest = Path(dirs["bsi"])
    dest.mkdir(parents=True, exist_ok=True)
    _sync_index(dest)
    _sync_csaf(dest)
