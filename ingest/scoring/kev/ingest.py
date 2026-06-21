"""Write the CISA KEV catalog into the `kev` table.

Pattern: DELETE + INSERT in one transaction. KEV is a small full snapshot and
CISA can withdraw entries, so the table is rebuilt each sync to match the source
exactly (withdrawn CVEs disappear). DELETE (not TRUNCATE) takes only ROW
EXCLUSIVE — concurrent dashboard SELECTs keep reading the old rows via MVCC until
commit, then see the new set atomically. No read blocking, no errors.
"""
import json
from pathlib import Path

from psycopg2.extras import execute_values


def _ransomware(v) -> bool | None:
    # CISA emits "Known" / "Unknown"; only "Known" is a confirmed campaign.
    if isinstance(v, str):
        return v.strip().lower() == "known"
    return None


def run(conn, dirs: dict) -> int:
    src = Path(dirs["kev"]) / "repo" / "known_exploited_vulnerabilities.json"
    if not src.exists():
        print(f"  kev: {src} not found — run `sync kev` first")
        return 0

    catalog = json.loads(src.read_bytes())
    rows = []
    for v in catalog.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        rows.append((
            cve,
            v.get("dateAdded") or None,
            v.get("dueDate") or None,
            _ransomware(v.get("knownRansomwareCampaignUse")),
            v.get("requiredAction") or None,
            v.get("vendorProject") or None,
            v.get("product") or None,
            v.get("vulnerabilityName") or None,
            v.get("shortDescription") or None,
            v.get("notes") or None,
        ))

    with conn.cursor() as cur:
        cur.execute("DELETE FROM kev")
        execute_values(cur, """
            INSERT INTO kev (
                cve_id, date_added, due_date, known_ransomware, required_action,
                vendor_project, product, vulnerability_name, short_description, notes
            ) VALUES %s
        """, rows, page_size=5_000)
    conn.commit()
    print(f"  kev: {len(rows):,} entries loaded (table rebuilt)")
    return len(rows)
