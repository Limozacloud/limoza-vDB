"""Ingest RedHat CSAF VEX files → cve_* (origin='redhat') + advisory/advisory_cve/cve_vendor.

Full re-ingest each run (delete_scope by origin/source, then reinsert) — idempotent.
Multiprocess: one DB connection per chunk, batched inserts. Phase-3 product status
(affected/fixed versions) is not written here.
"""
import multiprocessing as mp
import os
from pathlib import Path

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.redhat.transform import parse, transform

ORIGIN    = "redhat"
SOURCE    = "redhat"
BATCH     = 2_000
N_WORKERS = max(1, min(8, (os.cpu_count() or 2) - 1))


def _source_uuid(dsn: str):
    """RedHat's CNA orgId (so VEX cvss/cwe rows resolve to cna.uuids like its CNA data)."""
    import psycopg2
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT uuids[1] FROM cna WHERE short_name = %s", ("redhat",))
            r = cur.fetchone()
            return r[0] if r and r[0] else None
    finally:
        conn.close()


def _import_chunk(args):
    files, dsn, src = args
    import psycopg2
    from psycopg2.extras import Json

    conn = psycopg2.connect(dsn)
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for i, f in enumerate(files):
            try:
                rec = transform(parse(Path(f).read_bytes()), src)
            except Exception:
                continue
            if not rec:
                continue
            cid = rec["cve_id"]
            b["spine"].append((cid,))
            for s, v, sc, sev, vec in rec["cvss"]:
                b["cvss"].append((cid, ORIGIN, s, v, sc, sev, vec))
            for s, c in rec["cwe"]:
                b["cwe"].append((cid, ORIGIN, s, c))
            for s, u, t in rec["ref"]:
                b["ref"].append((cid, ORIGIN, s, u, t))
            for s, l, val in rec["desc"]:
                b["desc"].append((cid, ORIGIN, s, l, val))
            for s, l, val in rec["solution"]:
                b["solution"].append((cid, ORIGIN, s, l, val))
            for s, l, val in rec["workaround"]:
                b["workaround"].append((cid, ORIGIN, s, l, val))
            for s, cap, d in rec["impact"]:
                b["impact"].append((cid, ORIGIN, s, cap, d))
            for aid, url in rec["rhsa"].items():
                b["advisory"].append((SOURCE, aid, url))
                b["advisory_cve"].append((SOURCE, aid, cid))
            if rec["vendor_data"]:
                b["cve_vendor"].append((cid, SOURCE, Json(rec["vendor_data"])))
            n += 1
            if (i + 1) % BATCH == 0:
                flush(cur, b)
                conn.commit()
                b = new_bundle()
        flush(cur, b)
        conn.commit()
    conn.close()
    return n


def run(conn, dirs: dict) -> int:
    base = Path(dirs["redhat"]) / "vex"
    if not base.exists():
        print("  redhat: vex/ not found — run `sync redhat` first")
        return 0
    files = sorted(base.rglob("cve-*.json"))
    if not files:
        print("  redhat: no VEX files")
        return 0
    print(f"  redhat: {len(files):,} VEX files")

    dsn = os.environ["POSTGRES_DSN"]
    src = _source_uuid(dsn)
    print(f"  redhat: source uuid = {src}")

    delete_scope(conn, ORIGIN, SOURCE)

    workers = min(N_WORKERS, len(files))
    size = (len(files) + workers - 1) // workers
    chunks = [(files[i:i + size], dsn, src) for i in range(0, len(files), size)]

    total = 0
    with mp.Pool(workers) as pool:
        for n in pool.imap_unordered(_import_chunk, chunks):
            total += n
            print(f"  redhat: {total:,}/{len(files):,}", flush=True)

    enriched = _enrich_advisories(conn, Path(dirs["redhat"]) / "advisories")
    print(f"  redhat: {total:,} CVE-VEX records · {enriched:,} advisories enriched")
    return total


def _enrich_advisories(conn, adv_dir) -> int:
    """Fill advisory title/severity/dates by looking into the rhsa-*.json files —
    only for advisories already present (CVE-referenced via VEX). No new rows."""
    from psycopg2.extras import execute_values
    from ingest.advisories.redhat.transform import parse, parse_advisory

    if not adv_dir.exists():
        print("  redhat: advisories/ not found — skipping metadata enrichment")
        return 0
    rows = []
    for f in adv_dir.rglob("*.json"):
        try:
            m = parse_advisory(parse(f.read_bytes()))
        except Exception:
            continue
        if m:
            rows.append(m)
    if not rows:
        return 0
    with conn.cursor() as cur:
        execute_values(cur, """
            UPDATE advisory a SET
                title     = v.title,
                severity  = v.severity,
                published = v.published::timestamptz,
                modified  = v.modified::timestamptz,
                url       = COALESCE(v.url, a.url)
            FROM (VALUES %s) AS v(advisory_id, title, severity, published, modified, url)
            WHERE a.source = 'redhat' AND a.advisory_id = v.advisory_id
        """, rows, template="(%s,%s,%s,%s,%s,%s)", page_size=2_000)
        cur.execute("SELECT count(*) FROM advisory WHERE source='redhat' AND title IS NOT NULL")
        enriched = cur.fetchone()[0]
    conn.commit()
    return enriched
