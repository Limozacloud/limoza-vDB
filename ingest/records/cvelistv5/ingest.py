"""Ingest CVE List v5 records → cve spine + cve_record/cvss/cwe/desc/ref.

Incremental: tracks its own last-ingested commit (.ingest_head). On a repeat run
only the CVE files changed since then (git diff) are reparsed; on the first run
all of them. The changed CVEs' cvelistv5-origin info rows are deleted, then
reinserted, so a record losing data doesn't leave stale rows. Parsing is
parallelised (one DB connection per worker), like the v1 NVD importer.
"""
import multiprocessing as mp
import os
from pathlib import Path

from ingest.core.cveid import normalize
from ingest.core.gitsync import head
from ingest.core.incremental import git_changed_paths

ORIGIN     = "cvelistv5"
N_WORKERS  = mp.cpu_count()
BATCH      = 2_000
_INFO_TABLES = ("cve_cvss", "cve_cwe", "cve_desc", "cve_ref",
                "cve_solution", "cve_workaround", "cve_impact")


def _import_chunk(args):
    files, dsn, amap = args
    import psycopg2
    from psycopg2.extras import execute_values
    from ingest.records.cvelistv5.transform import parse, transform

    conn = psycopg2.connect(dsn)
    spine, records, cvss, cwe, desc, ref, sol, wrk, imp = [], [], [], [], [], [], [], [], []
    adp_acc = {}    # uuid -> [short_name, max_dateUpdated, count]
    cna_uuids = {}  # cna_id -> set(org uuids) (for cna.uuids backfill)
    n = 0

    def flush(cur):
        nonlocal n
        if spine:
            execute_values(cur, "INSERT INTO cve (cve_id) VALUES %s ON CONFLICT DO NOTHING", spine)
        if records:
            execute_values(cur, """
                INSERT INTO cve_record
                  (cve_id, state, assigner, date_reserved, date_published,
                   date_updated, title, exploit_note)
                VALUES %s
                ON CONFLICT (cve_id) DO UPDATE SET
                  state=EXCLUDED.state, assigner=EXCLUDED.assigner,
                  date_reserved=EXCLUDED.date_reserved, date_published=EXCLUDED.date_published,
                  date_updated=EXCLUDED.date_updated,
                  title=EXCLUDED.title, exploit_note=EXCLUDED.exploit_note, synced_at=now()
            """, records)
        if cvss:
            execute_values(cur, "INSERT INTO cve_cvss (cve_id,origin,source,version,base_score,severity,vector) VALUES %s ON CONFLICT (cve_id,source,vector) DO NOTHING", cvss)
        if cwe:
            execute_values(cur, "INSERT INTO cve_cwe (cve_id,origin,source,cwe_id) VALUES %s ON CONFLICT (cve_id,source,cwe_id) DO NOTHING", cwe)
        if desc:
            execute_values(cur, "INSERT INTO cve_desc (cve_id,origin,source,lang,value) VALUES %s ON CONFLICT (cve_id,source,lang) DO NOTHING", desc)
        if ref:
            execute_values(cur, "INSERT INTO cve_ref (cve_id,origin,source,url,type) VALUES %s ON CONFLICT (cve_id,source,url) DO NOTHING", ref)
        if sol:
            execute_values(cur, "INSERT INTO cve_solution (cve_id,origin,source,lang,value) VALUES %s ON CONFLICT (cve_id,source,lang) DO NOTHING", sol)
        if wrk:
            execute_values(cur, "INSERT INTO cve_workaround (cve_id,origin,source,lang,value) VALUES %s ON CONFLICT (cve_id,source,lang) DO NOTHING", wrk)
        if imp:
            execute_values(cur, "INSERT INTO cve_impact (cve_id,origin,source,capec_id,description) VALUES %s ON CONFLICT (cve_id,source,capec_id) DO NOTHING", imp)
        conn.commit()
        spine.clear(); records.clear(); cvss.clear(); cwe.clear(); desc.clear(); ref.clear()
        sol.clear(); wrk.clear(); imp.clear()

    with conn.cursor() as cur:
        for i, f in enumerate(files):
            try:
                rec = transform(parse(Path(f).read_bytes()))
            except Exception:
                continue
            if not rec:
                continue
            cid = rec["cve_id"]
            spine.append((cid,))
            assigner = amap.get(rec["assigner"], rec["assigner"])  # shortName → cna_id
            records.append((cid, rec["state"], assigner, rec["date_reserved"],
                            rec["date_published"], rec["date_updated"],
                            rec["title"], rec["exploit_note"]))
            if rec.get("assigner_uuid") and assigner.startswith(("CNA", "LVDB")):
                cna_uuids.setdefault(assigner, set()).add(rec["assigner_uuid"])
            for uid, sn, du in rec["adps"]:
                e = adp_acc.get(uid)
                if e:
                    if du and (e[1] is None or du > e[1]): e[1] = du
                    e[2] += 1
                else:
                    adp_acc[uid] = [sn, du, 1]
            for s, v, sc, sev, vec in rec["cvss"]:
                cvss.append((cid, ORIGIN, s, v, sc, sev, vec))
            for s, c in rec["cwe"]:
                cwe.append((cid, ORIGIN, s, c))
            for s, l, val in rec["desc"]:
                desc.append((cid, ORIGIN, s, l, val))
            for s, u, t in rec["ref"]:
                ref.append((cid, ORIGIN, s, u, t))
            for s, l, val in rec["solution"]:
                sol.append((cid, ORIGIN, s, l, val))
            for s, l, val in rec["workaround"]:
                wrk.append((cid, ORIGIN, s, l, val))
            for s, cap, d in rec["impact"]:
                imp.append((cid, ORIGIN, s, cap, d))
            n += 1
            if (i + 1) % BATCH == 0:
                flush(cur)
        flush(cur)

    conn.close()
    return n, adp_acc, cna_uuids


def _assigner_map(conn) -> dict:
    """shortName → cna_id, from cna.short_name and cna.aliases. Resolves drift so
    cve_record.assigner can hold the canonical cna_id (logical ref, no FK)."""
    m = {}
    with conn.cursor() as cur:
        cur.execute("SELECT short_name, cna_id FROM cna WHERE cna_id IS NOT NULL")
        m.update(cur.fetchall())
        cur.execute("SELECT unnest(aliases), cna_id FROM cna WHERE aliases IS NOT NULL AND cna_id IS NOT NULL")
        m.update(cur.fetchall())
    return m


def _delete_scope(conn, cve_ids):
    """Remove this origin's info rows so they can be cleanly reinserted."""
    with conn.cursor() as cur:
        for t in _INFO_TABLES:
            if cve_ids is None:
                cur.execute(f"DELETE FROM {t} WHERE origin = %s", (ORIGIN,))
            else:
                cur.execute(f"DELETE FROM {t} WHERE origin = %s AND cve_id = ANY(%s)", (ORIGIN, cve_ids))
    conn.commit()


def run(conn, dirs: dict) -> int:
    base = Path(dirs["cvelistv5"])
    repo = base / "repo"
    cves_dir = repo / "cves"
    if not cves_dir.exists():
        print("  cvelistv5: repo not found — run `sync cvelistv5` first")
        return 0

    state = base / ".ingest_head"
    current = head(repo)
    last = state.read_text().strip() if state.exists() else None

    if last and last != current:
        changed = git_changed_paths(repo, last, pathspec=["cves/"])
        files = [repo / p for p in changed if p.endswith(".json") and (repo / p).exists()]
        scope = [c for c in (normalize(Path(p).stem) for p in files) if c]
        print(f"  cvelistv5: {len(files):,} changed records since {last[:8]}")
        _delete_scope(conn, scope)
    elif last == current:
        print(f"  cvelistv5: already at {current[:8]} — nothing to ingest")
        return 0
    else:
        files = sorted(cves_dir.rglob("CVE-*.json"))
        print(f"  cvelistv5: first import — {len(files):,} records")
        _delete_scope(conn, None)

    if not files:
        if current:
            state.write_text(current)
        return 0

    dsn  = os.environ["POSTGRES_DSN"]
    amap = _assigner_map(conn)
    print(f"  cvelistv5: assigner map = {len(amap):,} shortName→cna_id")
    workers = min(N_WORKERS, len(files))
    size = (len(files) + workers - 1) // workers
    chunks = [(files[i:i + size], dsn, amap) for i in range(0, len(files), size)]

    total = 0
    adp_all, cna_uuids_all = {}, {}
    with mp.Pool(workers) as pool:
        for n, adp_acc, cna_uuids in pool.imap_unordered(_import_chunk, chunks):
            total += n
            for uid, (sn, du, c) in adp_acc.items():
                e = adp_all.get(uid)
                if e:
                    if du and (e[1] is None or du > e[1]): e[1] = du
                    e[2] += c
                else:
                    adp_all[uid] = [sn, du, c]
            for cid, s in cna_uuids.items():
                cna_uuids_all.setdefault(cid, set()).update(s)
            print(f"  cvelistv5: {total:,}/{len(files):,}", flush=True)

    _write_orgs(conn, adp_all, cna_uuids_all)

    if current:
        state.write_text(current)
    print(f"  cvelistv5: {total:,} records · {len(adp_all)} ADPs · {len(cna_uuids_all)} cna.uuids set")
    return total


def _write_orgs(conn, adp_all, cna_uuids_all):
    """Upsert the adp dictionary and backfill cna.uuids (incremental-safe: union)."""
    from psycopg2.extras import execute_values
    with conn.cursor() as cur:
        if adp_all:
            execute_values(cur, """
                INSERT INTO adp (uuid, short_name, last_updated) VALUES %s
                ON CONFLICT (uuid) DO UPDATE SET
                    short_name   = EXCLUDED.short_name,
                    last_updated = GREATEST(adp.last_updated, EXCLUDED.last_updated)
            """, [(u, v[0], v[1]) for u, v in adp_all.items()], page_size=500)
        for cna_id, uuids in cna_uuids_all.items():
            cur.execute("""
                UPDATE cna SET uuids = (
                    SELECT array_agg(DISTINCT u)
                    FROM unnest(coalesce(uuids, '{}'::text[]) || %s::text[]) AS t(u)
                ) WHERE cna_id = %s
            """, (sorted(uuids), cna_id))
    conn.commit()
