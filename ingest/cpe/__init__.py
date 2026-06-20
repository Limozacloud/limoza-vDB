"""CPE Dictionary import — loads cpe_dict.json into the `cpe` table."""
from __future__ import annotations

from ingest import json_compat as json
from pathlib import Path

from psycopg2.extras import execute_values

from ingest.cpe import validate as _validate

_BATCH = 2_000


def ingest(conn, dirs: dict, cve_filter=None) -> None:
    _validate.load(dirs.get("cpe", ""))

    src = Path(dirs["cpe"]) / "cpe_dict.json"
    if not src.exists():
        print(f"  ✗ {src} not found — run `sync cpe` + `sync cpe_index` first")
        return

    print(f"  Loading {src} ...")
    data: dict = json.loads(src.read_bytes())
    total = len(data)
    print(f"  {total:,} CPEs to import")

    rows = []
    done = 0

    def _flush():
        nonlocal done
        with conn.cursor() as cur:
            execute_values(cur, """
                INSERT INTO cpe (
                    cpe_name_id, cpe_uri, type, vendor, product, version,
                    title_en, deprecated, created_at, modified_at
                ) VALUES %s
                ON CONFLICT (cpe_name_id) DO UPDATE SET
                    cpe_uri     = EXCLUDED.cpe_uri,
                    type        = EXCLUDED.type,
                    vendor      = EXCLUDED.vendor,
                    product     = EXCLUDED.product,
                    version     = EXCLUDED.version,
                    title_en    = EXCLUDED.title_en,
                    deprecated  = EXCLUDED.deprecated,
                    created_at  = EXCLUDED.created_at,
                    modified_at = EXCLUDED.modified_at,
                    ingested_at = NOW()
            """, rows, page_size=_BATCH)
        conn.commit()
        done += len(rows)
        rows.clear()
        print(f"  [{done:>9,} / {total:,}]  {done/total*100:.1f}%")

    for name_id, entry in data.items():
        uri, cpe_type, vendor, product, version, title_en, deprecated, created, modified = entry
        rows.append((
            name_id, uri, cpe_type or None, vendor, product, version or None,
            title_en, bool(deprecated), created, modified,
        ))
        if len(rows) >= _BATCH:
            _flush()

    if rows:
        _flush()

    print(f"  Done. {done:,} CPEs imported.")
