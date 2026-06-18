"""Ingest Oracle Linux OVAL data."""
from pathlib import Path

from ingest.db import upsert_lve_record
from ingest.oracle.transform import parse_oval


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    xml_path = Path(dirs["oracle_oval"]) / "com.oracle.elsa-all.xml"
    if not xml_path.exists():
        print(f"  Oracle OVAL: {xml_path} not found — run `sync oracle` first")
        return

    total = skipped = errors = 0

    with conn.cursor() as cur:
        for i, record in enumerate(parse_oval(xml_path)):
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

            if not cve_filter and (i + 1) % 10000 == 0:
                conn.commit()
                print(f"  {i + 1} records...")

    conn.commit()
    print(f"  Oracle OVAL: {total} upserted · {skipped} skipped · {errors} errors")
