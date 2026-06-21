"""Write EPSS scores into the `epss` table.

Pattern: pure UPSERT keyed by cve_id. EPSS publishes a full daily snapshot and
never removes CVEs, so no sweep is needed — scores are simply overwritten.
"""
import json
from pathlib import Path

from psycopg2.extras import execute_values


def run(conn, dirs: dict) -> int:
    src = Path(dirs["epss"]) / "epss.json"
    if not src.exists():
        print(f"  epss: {src} not found — run `sync epss` first")
        return 0

    data = json.loads(src.read_text())
    rows = [
        (cve, float(v[0]), float(v[1]), v[2] if len(v) > 2 else None)
        for cve, v in data.items() if len(v) >= 2
    ]

    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO epss (cve_id, score, percentile, date) VALUES %s
            ON CONFLICT (cve_id) DO UPDATE SET
                score      = EXCLUDED.score,
                percentile = EXCLUDED.percentile,
                date       = EXCLUDED.date,
                synced_at  = now()
        """, rows, page_size=5_000)
    conn.commit()
    print(f"  epss: {len(rows):,} scores upserted")
    return len(rows)
