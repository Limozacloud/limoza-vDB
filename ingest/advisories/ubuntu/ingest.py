"""Ingest Ubuntu → cve_* (origin='ubuntu') + advisory/advisory_cve/cve_vendor.

OSV pass (per-CVE): cvss (computed from vectors) + desc + cve_vendor (Ubuntu priority).
USN pass (per-advisory): advisory metadata + advisory_cve (the CVE links).
Full re-ingest each run (delete_scope), idempotent.
"""
import multiprocessing as mp
import os
from pathlib import Path

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.ubuntu.transform import parse, transform_osv, parse_usn

ORIGIN    = "ubuntu"
SOURCE    = "ubuntu"
BATCH     = 2_000
N_WORKERS = max(1, min(8, (os.cpu_count() or 2) - 1))


def _source_uuid(dsn: str):
    import psycopg2
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT uuids[1] FROM cna WHERE lower(short_name) = ANY(%s)",
                        (["canonical", "ubuntu"],))
            r = cur.fetchone()
            return r[0] if r and r[0] else None
    finally:
        conn.close()


def _import_osv(args):
    files, dsn, src = args
    import psycopg2
    from psycopg2.extras import Json

    conn = psycopg2.connect(dsn)
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for i, f in enumerate(files):
            try:
                rec = transform_osv(parse(Path(f).read_bytes()), src)
            except Exception:
                continue
            if not rec:
                continue
            cid = rec["cve_id"]
            b["spine"].append((cid,))
            for s, v, sc, sev, vec in rec["cvss"]:
                b["cvss"].append((cid, ORIGIN, s, v, sc, sev, vec))
            for s, l, val in rec["desc"]:
                b["desc"].append((cid, ORIGIN, s, l, val))
            if rec["vendor_data"]:
                b["cve_vendor"].append((cid, SOURCE, Json(rec["vendor_data"])))
            n += 1
            if (i + 1) % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()
    conn.close()
    return n


def _ingest_usn(conn, usn_dir) -> int:
    if not usn_dir.exists():
        print("  ubuntu: usn/ not found — skipping advisory pass")
        return 0
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for i, f in enumerate(usn_dir.glob("*.json")):
            try:
                a = parse_usn(parse(f.read_bytes()))
            except Exception:
                continue
            if not a:
                continue
            uid, title, pub, cves = a
            if not cves:
                continue
            url = f"https://ubuntu.com/security/notices/{uid}"
            b["advisory"].append((SOURCE, uid, url, title, None, pub, None))
            for c in cves:
                b["spine"].append((c,))
                b["advisory_cve"].append((SOURCE, uid, c))
            n += 1
            if (i + 1) % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()
    return n


def run(conn, dirs: dict) -> int:
    base = Path(dirs["ubuntu"])
    osv_dir = base / "osv" / "cve"
    files = sorted(osv_dir.rglob("*.json")) if osv_dir.exists() else []
    print(f"  ubuntu: {len(files):,} OSV files")

    dsn = os.environ["POSTGRES_DSN"]
    src = _source_uuid(dsn)
    print(f"  ubuntu: source uuid = {src}")

    delete_scope(conn, ORIGIN, SOURCE)

    total = 0
    if files:
        workers = min(N_WORKERS, len(files))
        size = (len(files) + workers - 1) // workers
        chunks = [(files[i:i + size], dsn, src) for i in range(0, len(files), size)]
        with mp.Pool(workers) as pool:
            for n in pool.imap_unordered(_import_osv, chunks):
                total += n
                print(f"  ubuntu osv: {total:,}/{len(files):,}", flush=True)

    n_adv = _ingest_usn(conn, base / "usn")
    print(f"  ubuntu: {total:,} OSV records · {n_adv:,} USN advisories")
    return total
