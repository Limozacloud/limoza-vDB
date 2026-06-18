from pathlib import Path
from ingest.db import upsert_lve_record
from ingest.nvd.transform import parse, transform


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    nvd_path = Path(dirs["nvd"]) / "api"
    if not nvd_path.exists():
        print(f"  NVD: data not found at {nvd_path} — run `sync nvd` first")
        return

    if cve_filter:
        year  = cve_filter.split("-")[1]
        files = [nvd_path / year / f"{cve_filter}.json"]
        files = [f for f in files if f.exists()]
        print(f"  NVD: filter {cve_filter}")
    else:
        files = sorted(nvd_path.rglob("*.json"))
        print(f"  NVD: {len(files)} files")

    total = 0
    for i, f in enumerate(files):
        try:
            records = transform(parse(f.read_bytes()))
            with conn.cursor() as cur:
                for record in records:
                    upsert_lve_record(cur, record)
            total += len(records)
        except Exception as e:
            conn.rollback()
            print(f"  Error {f.name}: {e}")
            continue

        if (i + 1) % 10_000 == 0:
            conn.commit()
            print(f"  {i+1}/{len(files)} ({total} CVEs)")

    conn.commit()
    print(f"  NVD: {total} CVEs ingested")
