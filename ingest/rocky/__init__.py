"""Ingest Rocky Linux errata from updateinfo.xml + Apollo API advisories."""
import json
from pathlib import Path

from ingest.db import upsert_lve_record
from ingest.rocky.transform import parse_updateinfo, transform_advisories


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base    = Path(dirs["rocky_errata"])
    adv_dir = base / "advisories"

    if not base.exists():
        print(f"  Rocky errata: {base} not found — run `sync rocky` first")
        return

    xml_files = sorted(base.rglob("*.xml"))
    adv_files = sorted(adv_dir.glob("*.json")) if adv_dir.exists() else []

    if not xml_files and not adv_files:
        print("  Rocky errata: no data found — run `sync rocky` first")
        return

    print(f"  Rocky errata: {len(xml_files)} updateinfo files, {len(adv_files)} Apollo advisories")

    total = skipped = errors = i = 0

    def _upsert(record: dict) -> None:
        nonlocal total, skipped, errors, i
        cve_id = record["cve"]["cve_id"]
        if cve_filter and cve_id != cve_filter.upper():
            skipped += 1
            return
        with conn.cursor() as cur:
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

    # updateinfo.xml (bulk history)
    for xml_path in xml_files:
        major = xml_path.parent.name
        for record in parse_updateinfo(xml_path, major):
            _upsert(record)

    # Apollo API advisories (recent tail)
    if adv_files:
        advisories = []
        for f in adv_files:
            try:
                advisories.append(json.loads(f.read_bytes()))
            except Exception:
                pass
        for record in transform_advisories(advisories):
            _upsert(record)

    conn.commit()
    print(f"  Rocky: {total} upserted · {skipped} skipped · {errors} errors")
