"""Ingest Oracle Linux OVAL data."""
from pathlib import Path

from ingest.db import ingest_records
from ingest.oracle.transform import parse_oval


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    xml_path = Path(dirs["oracle_oval"]) / "com.oracle.elsa-all.xml"
    if not xml_path.exists():
        print(f"  Oracle OVAL: {xml_path} not found — run `sync oracle` first")
        return

    total, skipped, errors = ingest_records(
        conn,
        parse_oval(xml_path),
        label="Oracle OVAL",
        cve_filter=cve_filter,
    )
    print(f"  Oracle OVAL: {total} upserted · {skipped} skipped · {errors} errors")
