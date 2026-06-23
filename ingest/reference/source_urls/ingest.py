"""Seed the source_url table from advisories/source_urls.json (the editable single
source of truth). Gives cve_levels() an SQL-accessible mirror so it needs no
hardcoded URLs."""
import json
from pathlib import Path

from psycopg2.extras import execute_values

_JSON = Path(__file__).parents[2] / "advisories" / "source_urls.json"


def run(conn, dirs: dict) -> int:
    cfg = {k: v for k, v in json.loads(_JSON.read_text()).items() if not k.startswith("_")}
    rows = [(s, v.get("cve_url"), v.get("advisory_url"), v.get("when_id_prefix"))
            for s, v in cfg.items()]
    with conn.cursor() as cur:
        cur.execute("TRUNCATE source_url")
        execute_values(cur, "INSERT INTO source_url (source, cve_url, advisory_url, when_id_prefix) VALUES %s", rows)
    conn.commit()
    print(f"  source_urls: {len(rows)} sources seeded")
    return len(rows)
