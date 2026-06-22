"""Ingest Debian security-tracker → cve_desc + cve_vendor (origin/source='debian').

Single pass: load the tracker JSON, invert package→CVE, write description +
urgency/scope. Debian has no formal CVE-level advisory feed we can fetch, so no
advisory rows; per-release fixed versions are phase-3 affected.
"""
from pathlib import Path

from psycopg2.extras import Json

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.debian.transform import invert, parse

ORIGIN = "debian"
SOURCE = "debian"
BATCH  = 5_000


def run(conn, dirs: dict) -> int:
    f = Path(dirs["debian"]) / "tracker.json"
    if not f.exists():
        print("  debian: tracker.json not found — run `sync debian` first")
        return 0
    per = invert(parse(f.read_bytes()))
    print(f"  debian: {len(per):,} distinct CVEs")

    delete_scope(conn, ORIGIN, SOURCE)

    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for cid, e in per.items():
            b["spine"].append((cid,))
            if e["desc"]:
                b["desc"].append((cid, ORIGIN, None, "en", e["desc"]))   # Debian = non-CNA → source NULL
            data = {}
            if e["urgency"]:
                data["urgency"] = e["urgency"]
            if e["scope"]:
                data["scope"] = e["scope"]
            if data:
                b["cve_vendor"].append((cid, SOURCE, Json(data)))
            n += 1
            if n % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()
    print(f"  debian: {n:,} CVEs (desc + urgency/scope)")
    return n
