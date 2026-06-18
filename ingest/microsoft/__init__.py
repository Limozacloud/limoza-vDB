from pathlib import Path
from ingest.db import upsert_lve_record
from ingest.microsoft.transform import parse, transform
from ingest.cpe import validate as _cpe_validate


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    _cpe_validate.load(dirs.get("cpe", ""))
    base = Path(dirs["msrc"]) / "cvrf"
    if not base.exists():
        print(f"  Microsoft: data not found at {base} — run `sync microsoft` first")
        return

    files = sorted(base.glob("*.json"))
    print(f"  Microsoft: {len(files)} CVRF files" + (f" (filter: {cve_filter})" if cve_filter else ""))

    total = 0
    for f in files:
        try:
            records = transform(parse(f.read_bytes()))
            if cve_filter:
                records = [r for r in records if cve_filter in (r.get("aliases") or [])]
            with conn.cursor() as cur:
                for record in records:
                    upsert_lve_record(cur, record)
            conn.commit()
            total += len(records)
        except Exception as e:
            conn.rollback()
            print(f"  Error {f.name}: {e}")

    print(f"  Microsoft: {total} LVE records upserted")
