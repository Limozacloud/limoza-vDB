"""Ingest Alpine Linux secdb data."""
import json
from pathlib import Path

from ingest.db import upsert_lve_record
from ingest.alpine.transform import transform_file


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["alpine_secdb"])
    if not base.exists():
        print(f"  Alpine secdb: {base} not found — run `sync alpine` first")
        return

    files = sorted(f for f in base.rglob("*.json") if f.name != "checkpoint.json")
    print(f"  Alpine secdb: {len(files)} files")

    total = skipped = errors = 0

    with conn.cursor() as cur:
        for i, f in enumerate(files):
            try:
                data = json.loads(f.read_bytes())
            except Exception as e:
                print(f"  Alpine secdb: parse error {f}: {e}")
                continue

            for record in transform_file(data):
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

            if not cve_filter and (i + 1) % 5 == 0:
                conn.commit()

    conn.commit()
    print(f"  Alpine secdb: {total} upserted · {skipped} skipped · {errors} errors")
