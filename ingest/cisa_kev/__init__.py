from pathlib import Path
from ingest.db import upsert_lve_record
from ingest.cisa_kev.transform import parse, transform


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    index_path = Path(dirs["cisa_kev"]) / "kev_index.json"
    if not index_path.exists():
        print(f"  CISA KEV: {index_path} not found — run `sync cisa_kev` first")
        return

    data = parse(index_path.read_bytes())
    if cve_filter:
        data = {cve_filter: data[cve_filter]} if cve_filter in data else {}
        print(f"  CISA KEV: filter {cve_filter}")
    else:
        print(f"  CISA KEV: {len(data)} entries")

    records = transform(data)
    with conn.cursor() as cur:
        for record in records:
            upsert_lve_record(cur, record)

    conn.commit()
    print(f"  CISA KEV: {len(records)} entries ingested")
