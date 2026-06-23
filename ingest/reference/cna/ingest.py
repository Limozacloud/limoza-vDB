"""Write the CNA list into the `cna` table, then apply cna_mapping.json.

Two sources:
  cnas.json (synced)         — the official CVE Program partner list (CNAsList).
  cna_mapping.json (bundled) — our curated supplements: record-shortName aliases
                               that drift from the canonical name, plus self-owned
                               org rows (LVDB-CNA-*) for orgs missing from the list.

Pattern:
  official rows  → UPSERT + soft sweep (active=false when dropped from the list).
  aliases        → rebuilt from the mapping each run (mapping is the source of truth).
  self rows      → UPSERT; LVDB rows no longer in the mapping are hard-deleted.
"""
import datetime
import json
from pathlib import Path

from psycopg2.extras import execute_values

_MAPPING = Path(__file__).parent / "cna_mapping.json"


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
        rows.append((
            name, d.get("cnaID"), d.get("organizationName"), d.get("scope"),
            advisories[0].get("url") if advisories else None, run_ts,
        ))

    mapping = json.loads(_MAPPING.read_text()) if _MAPPING.exists() else []
    official = [m for m in mapping if (m.get("cna_id") or "").startswith("CNA")]
    selfown  = [m for m in mapping if (m.get("cna_id") or "").startswith("LVDB")]

    with conn.cursor() as cur:
        # 1. official partner list
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

        # 2. self-owned org rows (LVDB-CNA-*) from the mapping
        if selfown:
            execute_values(cur, """
                INSERT INTO cna (short_name, cna_id, organization_name, advisory_url, active, aliases, synced_at)
                VALUES %s
                ON CONFLICT (short_name) DO UPDATE SET
                    cna_id            = EXCLUDED.cna_id,
                    organization_name = EXCLUDED.organization_name,
                    advisory_url      = EXCLUDED.advisory_url,
                    active            = EXCLUDED.active,
                    aliases           = EXCLUDED.aliases,
                    synced_at         = EXCLUDED.synced_at
            """, [(m["short_name"], m["cna_id"], m.get("organization_name"),
                   m.get("advisory_url"), bool(m.get("active", True)), m["alias"], run_ts)
                  for m in selfown], page_size=500)

        # 3. aliases: rebuilt from the mapping (source of truth) — clear official, then set.
        #    Union aliases per cna_id so duplicate mapping entries don't overwrite each other.
        agg = {}
        for m in official:
            agg.setdefault(m["cna_id"], set()).update(m["alias"])
        cur.execute("UPDATE cna SET aliases = NULL WHERE aliases IS NOT NULL AND cna_id LIKE 'CNA%'")
        for cid, al in agg.items():
            cur.execute("UPDATE cna SET aliases = %s WHERE cna_id = %s", (sorted(al), cid))

        # 4. drop self rows no longer in the mapping
        keep = [m["cna_id"] for m in selfown]
        cur.execute("DELETE FROM cna WHERE cna_id LIKE 'LVDB-%%' AND NOT (cna_id = ANY(%s))", (keep,))
        dropped = cur.rowcount

    conn.commit()
    print(f"  cna: {len(rows):,} official · {len(selfown)} self · "
          f"{len(official)} alias-sets · {deactivated} deactivated · {dropped} self-dropped")
    return len(rows)
