"""Sync OSV vulnerability data from GCS and build CVE→file index.

Downloads per-ecosystem zip files from the OSV GCS bucket into /data/osv/,
then scans all files and builds a {cve_id: [relative_paths]} index.

Ecosystems downloaded: AlmaLinux, Rocky Linux, Red Hat, Debian, Ubuntu, Alpine.
"""
import concurrent.futures
import io
from ingest import json_compat as json
import threading
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

_GCS_BASE  = "https://osv-vulnerabilities.storage.googleapis.com"
_WORKERS   = 16

# OS ecosystems — downloaded for OSV comparison (compare.py / verify command)
OS_ECOSYSTEMS = [
    "AlmaLinux",
    "Rocky Linux",
    "Red Hat",
    "Debian",
    "Ubuntu",
    "Alpine",
]

# Package ecosystems — imported into DB via ingest function
PKG_ECOSYSTEMS = [
    "PyPI",
    "npm",
    "Go",
    "crates.io",
    "RubyGems",
    "NuGet",
    "Maven",
    "Packagist",
    "Hex",
    "Pub",
]

ECOSYSTEMS = OS_ECOSYSTEMS + PKG_ECOSYSTEMS


def _eco_dir(base: Path, eco: str) -> Path:
    return base / eco.replace(" ", "_")


def _download_ecosystem(base: Path, eco: str) -> int:
    eco_dir = _eco_dir(base, eco)
    eco_dir.mkdir(parents=True, exist_ok=True)
    url  = f"{_GCS_BASE}/{urllib.request.quote(eco, safe='')}/all.zip"
    print(f"    {eco}: downloading...")
    try:
        req  = urllib.request.Request(url, headers={"User-Agent": "limoza-ingest/1.0"})
        data = urllib.request.urlopen(req, timeout=300).read()
    except Exception as e:
        print(f"    {eco}: skip ({e})")
        return 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(eco_dir)
    count = sum(1 for _ in eco_dir.glob("*.json"))
    print(f"    {eco}: {count} files")
    return count


def _build_index(base: Path) -> dict:
    all_files = [f for f in base.rglob("*.json") if f.name != "osv_index.json"]
    total     = len(all_files)
    print(f"  Indexing {total} files...")

    index: dict[str, list[str]] = {}
    lock  = threading.Lock()
    done  = 0

    def _process(f: Path) -> None:
        nonlocal done
        try:
            raw = f.read_bytes()
            if b'"CVE-' not in raw:
                with lock:
                    done += 1
                return
            data   = json.loads(raw)
            adv_id = data.get("id", "")
            if adv_id.startswith("CVE-"):
                with lock:
                    done += 1
                return
            refs = (
                (data.get("related")  or []) +
                (data.get("aliases")  or []) +
                (data.get("upstream") or [])
            )
            cves = [r for r in refs if r.startswith("CVE-")]
            if cves:
                rel = str(f.relative_to(base))
                with lock:
                    for cve in cves:
                        index.setdefault(cve, []).append(rel)
            with lock:
                done += 1
                if done % 10000 == 0:
                    print(f"    {done}/{total}...")
        except Exception:
            with lock:
                done += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        list(pool.map(_process, all_files))

    print(f"  Index: {len(index)} CVEs → {total} advisory files")
    return index


def sync(dirs: dict) -> None:
    base = Path(dirs["osv"])
    base.mkdir(parents=True, exist_ok=True)

    print(f"  OSV: syncing {len(ECOSYSTEMS)} ecosystems...")
    for eco in ECOSYSTEMS:
        _download_ecosystem(base, eco)

    print("  OSV: building index...")
    index = _build_index(base)
    (base / "osv_index.json").write_bytes(
        json.dumps(index, separators=(",", ":")).encode()
    )

    now = datetime.now(timezone.utc).isoformat()
    (base / "checkpoint.json").write_bytes(
        json.dumps({"last_sync": now}, separators=(",", ":")).encode()
    )
    print(f"  OSV: checkpoint updated: {now}")
