"""Ingest Rocky Linux errata from updateinfo.xml + Apollo API advisories."""
from ingest import json_compat as json
from pathlib import Path

from ingest.db import ingest_records
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

    total = skipped = errors = 0

    def _xml_records():
        for xml_path in xml_files:
            major = xml_path.parent.name
            yield from parse_updateinfo(xml_path, major)

    t, s, e = ingest_records(conn, _xml_records(), label="Rocky XML", cve_filter=cve_filter)
    total += t; skipped += s; errors += e

    if adv_files:
        advisories = []
        for f in adv_files:
            try:
                advisories.append(json.loads(f.read_bytes()))
            except Exception:
                pass
        t, s, e = ingest_records(conn, transform_advisories(advisories),
            label="Rocky advisories", cve_filter=cve_filter)
        total += t; skipped += s; errors += e

    print(f"  Rocky: {total:,} upserted · {skipped} skipped · {errors} errors")
