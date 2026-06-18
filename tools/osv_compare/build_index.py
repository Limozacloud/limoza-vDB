"""Build CVE→[filenames] index from local OSV dump.

Usage:
    python tools/osv_compare/build_index.py
    python tools/osv_compare/build_index.py --osv-dir D:/osv/all
    python tools/osv_compare/build_index.py --reindex   (force rebuild)

Skips MAL-* files (malware records, no CVE advisory refs) and CGA-* files.
Index saved as osv_index.json next to this script.
"""
import argparse
import concurrent.futures
import json
import re
import threading
import time
from pathlib import Path

OSV_DIR_DEFAULT = Path(r"C:\Users\Henrik\Downloads\all")
INDEX_PATH      = Path(__file__).parent / "osv_index.json"

# Prefixes that never contain CVE advisory references — skip for speed
SKIP_PREFIXES = ("MAL-", "CGA-", "MINI-", "ROOT-", "BELL-", "GSD-", "BIT-")

CVE_RE = re.compile(rb'"CVE-(\d{4}-\d+)"')


def build_index(osv_dir: Path) -> dict:
    all_files = [
        f for f in osv_dir.glob("*.json")
        if not any(f.name.startswith(p) for p in SKIP_PREFIXES)
    ]
    total = len(all_files)
    print(f"  {total} files to index (skipped MAL/CGA/MINI/ROOT/BELL/GSD/BIT)")

    index: dict[str, list[str]] = {}
    lock   = threading.Lock()
    done   = 0
    errors = 0
    t0     = time.time()

    def _process(f: Path) -> None:
        nonlocal done, errors
        try:
            raw = f.read_bytes()
            # Quick pre-filter: skip if no CVE string at all
            if b'"CVE-' not in raw:
                with lock:
                    done += 1
                return

            data = json.loads(raw)
            adv_id = data.get("id", "")
            # Skip CVE entries themselves — we want advisory→CVE mapping
            if adv_id.startswith("CVE-"):
                with lock:
                    done += 1
                return

            refs = (
                (data.get("related")  or []) +
                (data.get("aliases")  or []) +
                (data.get("upstream") or [])
            )
            cve_refs = [r for r in refs if r.startswith("CVE-")]
            if not cve_refs:
                with lock:
                    done += 1
                return

            with lock:
                for cve in cve_refs:
                    index.setdefault(cve, []).append(f.name)
                done += 1
                if done % 10000 == 0:
                    elapsed = time.time() - t0
                    rate    = done / elapsed
                    eta     = (total - done) / rate if rate else 0
                    print(f"  {done}/{total}  ({rate:.0f} files/s  ETA {eta:.0f}s)")
        except Exception:
            with lock:
                errors += 1
                done   += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(_process, all_files))

    elapsed = time.time() - t0
    print(f"  Done: {total} files in {elapsed:.1f}s — {len(index)} CVEs indexed, {errors} errors")
    return index


def main():
    ap = argparse.ArgumentParser(description="Build OSV CVE→filename index")
    ap.add_argument("--osv-dir",  type=Path, default=OSV_DIR_DEFAULT)
    ap.add_argument("--reindex",  action="store_true", help="Force rebuild even if index exists")
    ap.add_argument("--out",      type=Path, default=INDEX_PATH)
    args = ap.parse_args()

    if args.out.exists() and not args.reindex:
        data = json.loads(args.out.read_bytes())
        print(f"Index already exists: {len(data)} CVEs — use --reindex to rebuild")
        return

    print(f"Building index from {args.osv_dir}...")
    index = build_index(args.osv_dir)
    args.out.write_bytes(json.dumps(index, separators=(",", ":")).encode())
    print(f"Saved to {args.out}")


if __name__ == "__main__":
    main()
