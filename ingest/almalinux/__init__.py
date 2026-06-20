"""Ingest AlmaLinux errata data."""
from ingest import json_compat as json
from pathlib import Path

from ingest.db import ingest_records
from ingest.almalinux.transform import transform_advisories


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["almalinux_errata"])
    if not base.exists():
        print(f"  AlmaLinux errata: {base} not found — run `sync almalinux` first")
        return

    version_files = sorted(base.glob("[0-9]*.json"))
    if not version_files:
        print("  AlmaLinux errata: no version files found")
        return

    total = skipped = errors = 0
    for vf in version_files:
        major = vf.stem
        data  = json.loads(vf.read_bytes())
        print(f"  AlmaLinux {major}: {len(data)} advisories")
        t, s, e = ingest_records(conn, transform_advisories(data, major),
            label=f"AlmaLinux {major}", cve_filter=cve_filter)
        total += t; skipped += s; errors += e

    print(f"  AlmaLinux: {total:,} upserted · {skipped} skipped · {errors} errors")
