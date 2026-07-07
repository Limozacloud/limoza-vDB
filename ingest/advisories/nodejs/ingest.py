"""Ingest Node.js core security (nodejs/security-wg → vuln/core).

Enrichment only — the version-precise affected ranges are derived by the L4 pass
(``ingest.affected.sources.nodejs``) from the same ``patched`` field. Here we write:
  - the cve spine (ON CONFLICT DO NOTHING)
  - cve_desc  (the advisory overview/description)  origin='nodejs'
  - cve_vendor (severity + the nodejs.org security-release ref)  source='nodejs'

An entry may list several CVEs (one flaw, multiple ids) or none (pre-CVE node
advisory) — the latter we skip, since the CVE id is our only join key.
"""
import json
from pathlib import Path

from psycopg2.extras import Json

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "nodejs"
BATCH  = 1_000


def _entries(base: Path):
    """Yield the core-vuln entries from index.json (a dict id → entry)."""
    idx = base / "vuln" / "core" / "index.json"
    if not idx.exists():
        return
    d = json.loads(idx.read_bytes())
    yield from (d.values() if isinstance(d, dict) else d)


def run(conn, dirs: dict) -> int:
    base = Path(dirs["nodejs"])
    if not (base / "vuln" / "core").exists():
        print("  nodejs: no data — run `sync nodejs` first")
        return 0

    delete_scope(conn, ORIGIN, SOURCE)

    b = new_bundle()
    seen_desc = set()
    n = 0
    with conn.cursor() as cur:
        for e in _entries(base):
            cids = [normalize(c) for c in (e.get("cve") or []) if normalize(c)]
            if not cids:
                continue                       # no CVE id → nothing to join on
            desc = (e.get("overview") or e.get("description") or "").strip() or None
            sev = (e.get("severity") or "").strip().lower() or None
            ref = e.get("ref")
            data = {k: v for k, v in {"severity": sev, "ref": ref,
                                      "description": e.get("description")}.items() if v}
            for cid in cids:
                b["spine"].append((cid,))
                if desc and cid not in seen_desc:
                    seen_desc.add(cid)
                    b["desc"].append((cid, ORIGIN, SOURCE, "en", desc))
                b["cve_vendor"].append((cid, SOURCE, Json(data)))
            n += 1
            if n % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()

    print(f"  nodejs: {n:,} core advisories")
    return n
