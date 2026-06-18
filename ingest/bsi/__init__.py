from pathlib import Path
from ingest.db import upsert_lve_record
from ingest.bsi.transform import transform

_BATCH = 5_000


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    bsi_dir    = Path(dirs["bsi"])
    index_path = bsi_dir / "bsi_index.json"
    csaf_dir   = bsi_dir / "csaf"

    if not index_path.exists():
        print(f"  BSI: {index_path} not found — run `sync bsi` first")
        return

    import json
    idx = json.loads(index_path.read_bytes())

    has_csaf = csaf_dir.exists() and any(csaf_dir.iterdir())

    if cve_filter:
        idx = {cve_filter: idx[cve_filter]} if cve_filter in idx else {}
        print(f"  BSI: filter {cve_filter}")
    else:
        print(f"  BSI: {len(idx)} CVEs" + (" (with CSAF)" if has_csaf else " (index only — run `sync bsi` for titles)"))

    total = errors = 0
    with conn.cursor() as cur:
        for i, (cve_id, entry) in enumerate(idx.items()):
            wid_id  = entry.get("wid_id", "")
            wid_url = entry.get("wid_url", "")
            if not wid_id:
                continue
            try:
                cur.execute("SAVEPOINT sp")
                record = transform(cve_id, wid_id, wid_url,
                                   csaf_dir if has_csaf else None)
                upsert_lve_record(cur, record)
                total += 1
                cur.execute("RELEASE SAVEPOINT sp")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                errors += 1
                if errors <= 5:
                    print(f"  BSI error {cve_id}: {e}")

            if not cve_filter and (i + 1) % _BATCH == 0:
                conn.commit()
                print(f"  {i+1}/{len(idx)}")

    conn.commit()
    print(f"  BSI: {total} upserted · {errors} errors")
