from pathlib import Path
from ingest.db import upsert_lve_record
from ingest.epss.transform import parse, transform

_BATCH = 50_000


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    index_path = Path(dirs["epss"]) / "epss.json"
    if not index_path.exists():
        print(f"  EPSS: {index_path} not found — run `sync epss` first")
        return

    data = parse(index_path.read_bytes())
    if cve_filter:
        data = {cve_filter: data[cve_filter]} if cve_filter in data else {}
        print(f"  EPSS: filter {cve_filter}")
    else:
        print(f"  EPSS: {len(data)} scores")

    records = transform(data)
    total = 0
    with conn.cursor() as cur:
        for record in records:
            upsert_lve_record(cur, record)
            total += 1
            if total % _BATCH == 0:
                conn.commit()
                print(f"  {total}/{len(records)}")

    conn.commit()
    print(f"  EPSS: {total} scores ingested")
