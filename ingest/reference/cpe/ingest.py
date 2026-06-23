"""Write the CPE dictionary into the `cpe` table.

Pattern: pure UPSERT, batched. CPE entries are deprecated (deprecated=true),
never deleted — so no sweep. ~1.7M rows; committed per batch.
"""
import json
from pathlib import Path

from psycopg2.extras import execute_values

_BATCH = 5_000


def run(conn, dirs: dict) -> int:
    src = Path(dirs["cpe"]) / "cpe_dict.json"
    if not src.exists():
        print(f"  cpe: {src} not found — run `sync cpe` first")
        return 0

    data = json.loads(src.read_bytes())
    total = len(data)
    print(f"  cpe: {total:,} entries to upsert")

    rows, done = [], 0

    def flush():
        nonlocal done
        with conn.cursor() as cur:
            execute_values(cur, """
                INSERT INTO cpe (cpe_name_id, cpe_uri, type, vendor, product, version,
                    title_en, deprecated, created_at, modified_at) VALUES %s
                ON CONFLICT (cpe_name_id) DO UPDATE SET
                    cpe_uri = EXCLUDED.cpe_uri, type = EXCLUDED.type,
                    vendor = EXCLUDED.vendor, product = EXCLUDED.product,
                    version = EXCLUDED.version, title_en = EXCLUDED.title_en,
                    deprecated = EXCLUDED.deprecated, created_at = EXCLUDED.created_at,
                    modified_at = EXCLUDED.modified_at, ingested_at = now()
            """, rows, page_size=_BATCH)
        conn.commit()
        done += len(rows)
        rows.clear()
        print(f"  [{done:>9,} / {total:,}]  {done/total*100:.1f}%")

    for name_id, e in data.items():
        uri, ctype, vendor, product, version, title_en, deprecated, created, modified = e
        rows.append((name_id, uri, ctype or None, vendor, product, version or None,
                     title_en, bool(deprecated), created, modified))
        if len(rows) >= _BATCH:
            flush()
    if rows:
        flush()

    print(f"  cpe: {done:,} entries upserted")
    return done
