"""Write CISA SSVC decisions into the `ssvc` table.

Pattern: DELETE + INSERT in one transaction. DELETE (not TRUNCATE) takes only
ROW EXCLUSIVE, so concurrent dashboard SELECTs keep reading old rows via MVCC
until commit — no read blocking on this ~156k-row table. SSVC values are
normalised to lowercase to match the schema CHECK constraints; rows missing a
valid exploitation value are skipped.
"""
import json
from pathlib import Path

from psycopg2.extras import execute_values

_EXPLOITATION = {"none": "none", "poc": "poc", "active": "active"}
_AUTOMATABLE  = {"yes": "yes", "no": "no"}
_IMPACT       = {"partial": "partial", "total": "total"}


def _norm(value, mapping):
    return mapping.get(value.lower()) if value else None


def run(conn, dirs: dict) -> int:
    src = Path(dirs["ssvc"]) / "ssvc_index.json"
    if not src.exists():
        print(f"  ssvc: {src} not found — run `sync ssvc` first")
        return 0

    data = json.loads(src.read_text())
    rows = []
    for cve, e in data.items():
        exploitation = _norm(e.get("exploitation"), _EXPLOITATION)
        if not exploitation:
            continue
        rows.append((
            cve,
            exploitation,
            _norm(e.get("automatable"), _AUTOMATABLE),
            _norm(e.get("technical_impact"), _IMPACT),
        ))

    with conn.cursor() as cur:
        cur.execute("DELETE FROM ssvc")
        execute_values(cur, """
            INSERT INTO ssvc (cve_id, exploitation, automatable, technical_impact) VALUES %s
        """, rows, page_size=5_000)
    conn.commit()
    print(f"  ssvc: {len(rows):,} decisions loaded (table rebuilt)")
    return len(rows)
