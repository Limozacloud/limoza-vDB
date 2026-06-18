from pathlib import Path
from ingest.db import upsert_lve_record
from ingest.cisa_ssvc.transform import parse, transform


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    index_path = Path(dirs["cisa_ssvc"]) / "ssvc_index.json"
    if not index_path.exists():
        print(f"  CISA SSVC: {index_path} not found — run `sync cisa_ssvc` first")
        return

    data = parse(index_path.read_bytes())
    if cve_filter:
        data = {cve_filter: data[cve_filter]} if cve_filter in data else {}
        print(f"  CISA SSVC: filter {cve_filter}")
    else:
        print(f"  CISA SSVC: {len(data)} CVEs")

    records = transform(data)
    with conn.cursor() as cur:
        for record in records:
            upsert_lve_record(cur, record)

    conn.commit()
    print(f"  CISA SSVC: {len(records)} entries ingested")
