"""Ingest AlmaLinux errata data."""
import json
from pathlib import Path

from ingest.db import upsert_lve_record
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

    total = skipped = errors = i = 0

    with conn.cursor() as cur:
        for vf in version_files:
            major = vf.stem  # "8", "9", "10"
            data  = json.loads(vf.read_bytes())
            print(f"  AlmaLinux: {len(data)} advisories in {major}")

            for record in transform_advisories(data, major):
                cve_id = record["cve"]["cve_id"]
                if cve_filter and cve_id != cve_filter.upper():
                    skipped += 1
                    continue
                try:
                    cur.execute("SAVEPOINT sp")
                    upsert_lve_record(cur, record)
                    total += 1
                    cur.execute("RELEASE SAVEPOINT sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT sp")
                    errors += 1
                    if errors <= 5:
                        print(f"  Error {cve_id}: {e}")

                i += 1
                if not cve_filter and i % 10000 == 0:
                    conn.commit()
                    print(f"  {i} records...")

    conn.commit()
    print(f"  AlmaLinux: {total} upserted · {skipped} skipped · {errors} errors")
