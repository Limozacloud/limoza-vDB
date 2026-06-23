"""Ingest SUSE CSAF → cve_* (origin='suse') + advisory/advisory_cve/cve_vendor.

VEX pass (per-CVE): enrichment + cve_vendor. SUSE VEX has no advisory refs.
Advisory pass (per-SUSE-SU): advisory metadata + advisory_cve (the CVE links).
Full re-ingest each run (delete_scope), idempotent.
"""
import multiprocessing as mp
import os
from pathlib import Path

from ingest.advisories import advisory_url, delete_scope, flush, new_bundle, vendor_row
from ingest.advisories.suse.transform import parse, transform_vex, parse_advisory

ORIGIN    = "suse"
SOURCE    = "suse"
BATCH     = 2_000
N_WORKERS = max(1, min(8, (os.cpu_count() or 2) - 1))


def _source_uuid(dsn: str):
    import psycopg2
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT uuids[1] FROM cna WHERE lower(short_name) = %s", ("suse",))
            r = cur.fetchone()
            return r[0] if r and r[0] else None
    finally:
        conn.close()


def _import_vex(args):
    files, dsn, src = args
    import psycopg2

    conn = psycopg2.connect(dsn)
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for i, f in enumerate(files):
            try:
                rec = transform_vex(parse(Path(f).read_bytes()), src)
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
            for s, l, val in rec["workaround"]:
                b["workaround"].append((cid, ORIGIN, s, l, val))
            if rec["vendor_data"]:
                b["cve_vendor"].append(vendor_row(SOURCE, cid, rec["vendor_data"]))
            n += 1
            if (i + 1) % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()
    conn.close()
    return n


def _ingest_advisories(conn, adv_dir) -> int:
    """Per-SUSE-SU advisory metadata + advisory_cve (the CVE links live here)."""
    if not adv_dir.exists():
        print("  suse: advisories/ not found — skipping advisory pass")
        return 0
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for i, f in enumerate(adv_dir.rglob("*.json")):
            try:
                a = parse_advisory(parse(f.read_bytes()))
            except Exception:
                continue
            if not a:
                continue
            aid, title, sev, pub, mod, url, cves = a
            if not cves:
                continue
            b["advisory"].append((SOURCE, aid, advisory_url(SOURCE, aid) or url, title, sev, pub, mod))
            for c in cves:
                b["spine"].append((c,))
                b["advisory_cve"].append((SOURCE, aid, c))
            n += 1
            if (i + 1) % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()
    return n


def run(conn, dirs: dict) -> int:
    base = Path(dirs["suse"])
    vex_dir = base / "vex"
    if not vex_dir.exists():
        print("  suse: vex/ not found — run `sync suse` first")
        return 0
    files = sorted(vex_dir.rglob("cve-*.json"))
    print(f"  suse: {len(files):,} VEX files")

    dsn = os.environ["POSTGRES_DSN"]
    src = _source_uuid(dsn)
    print(f"  suse: source uuid = {src}")

    delete_scope(conn, ORIGIN, SOURCE)

    total = 0
    if files:
        workers = min(N_WORKERS, len(files))
        size = (len(files) + workers - 1) // workers
        chunks = [(files[i:i + size], dsn, src) for i in range(0, len(files), size)]
        with mp.Pool(workers) as pool:
            for n in pool.imap_unordered(_import_vex, chunks):
                total += n
                print(f"  suse vex: {total:,}/{len(files):,}", flush=True)

    n_adv = _ingest_advisories(conn, base / "advisories")
    print(f"  suse: {total:,} VEX records · {n_adv:,} advisories")
    return total
