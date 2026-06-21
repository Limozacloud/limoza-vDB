"""Write the CNA list into the `cna` table.

Pattern: UPSERT + SOFT sweep. Advisories reference cna.short_name, so a CNA that
disappears from the list is marked active=false (tombstone) instead of deleted.
All rows touched this run get synced_at=run_ts and active=true; rows with an
older synced_at were not in this run → deactivated.
"""
import datetime
import json
from pathlib import Path

from psycopg2.extras import execute_values


def run(conn, dirs: dict) -> int:
    src = Path(dirs["cna"]) / "cnas.json"
    if not src.exists():
        print(f"  cna: {src} not found — run `sync cna` first")
        return 0

    data = json.loads(src.read_text())
    run_ts = datetime.datetime.now(datetime.timezone.utc)

    rows = []
    for d in data:
        name = d.get("shortName")
        if not name:
            continue
        advisories = d.get("securityAdvisories", {}).get("advisories", [])
        advisory_url = advisories[0].get("url") if advisories else None
        rows.append((
            name,
            d.get("cnaID"),
            d.get("organizationName"),
            d.get("scope"),
            advisory_url,
            run_ts,
        ))

    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO cna (short_name, cna_id, organization_name, scope, advisory_url, synced_at)
            VALUES %s
            ON CONFLICT (short_name) DO UPDATE SET
                cna_id            = EXCLUDED.cna_id,
                organization_name = EXCLUDED.organization_name,
                scope             = EXCLUDED.scope,
                advisory_url      = EXCLUDED.advisory_url,
                active            = TRUE,
                synced_at         = EXCLUDED.synced_at
        """, rows, page_size=2_000)
        cur.execute("UPDATE cna SET active = FALSE WHERE synced_at < %s AND active", (run_ts,))
        deactivated = cur.rowcount
    conn.commit()
    print(f"  cna: {len(rows):,} upserted · {deactivated} deactivated (no longer listed)")
    return len(rows)
