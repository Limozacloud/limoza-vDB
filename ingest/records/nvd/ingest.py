"""Ingest NVD CVE 2.0 records → cve spine + cve_cvss/cwe/desc/ref (origin='nvd').

NVD is a multi-source ENRICHER: it adds its own descriptions, CVSS, CWE and references
alongside cvelistv5. It does NOT own cve_record (the spine record — assigner/title/dates —
stays cvelistv5's). Incremental via the nvd-sync repo's git head (only changed CVEs are
reparsed on a repeat run); the changed CVEs' nvd-origin info rows are deleted then
reinserted. Parsing is parallelised (one DB connection per worker).
"""
import multiprocessing as mp
import os
from pathlib import Path

from ingest.core.cveid import normalize
from ingest.core.gitsync import head
from ingest.core.incremental import git_changed_paths

ORIGIN = "nvd"
N_WORKERS = mp.cpu_count()
BATCH = 2_000
_INFO_TABLES = ("cve_cvss", "cve_cwe", "cve_desc", "cve_ref")


def _import_chunk(args):
    files, dsn = args
    import psycopg2
    from psycopg2.extras import execute_values

    from ingest.records.nvd.transform import parse, transform

    conn = psycopg2.connect(dsn)
    spine, cvss, cwe, desc, ref = [], [], [], [], []
    n = 0

    def flush(cur):
        nonlocal n
        if spine:
            execute_values(cur, "INSERT INTO cve (cve_id) VALUES %s ON CONFLICT DO NOTHING", spine)
        if cvss:
            execute_values(cur, "INSERT INTO cve_cvss (cve_id,origin,source,version,base_score,severity,vector) VALUES %s ON CONFLICT (cve_id,origin,source,vector) DO NOTHING", cvss)
        if cwe:
            execute_values(cur, "INSERT INTO cve_cwe (cve_id,origin,source,cwe_id) VALUES %s ON CONFLICT (cve_id,origin,source,cwe_id) DO NOTHING", cwe)
        if desc:
            execute_values(cur, "INSERT INTO cve_desc (cve_id,origin,source,lang,value) VALUES %s ON CONFLICT (cve_id,origin,source,lang) DO NOTHING", desc)
        if ref:
            execute_values(cur, "INSERT INTO cve_ref (cve_id,origin,source,url,type) VALUES %s ON CONFLICT (cve_id,origin,source,url) DO NOTHING", ref)
        conn.commit()
        spine.clear(); cvss.clear(); cwe.clear(); desc.clear(); ref.clear()

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
            for ver, sc, sev, vec in rec["cvss"]:
                cvss.append((cid, ORIGIN, ORIGIN, ver, sc, sev, vec))
            for c in rec["cwe"]:
                cwe.append((cid, ORIGIN, ORIGIN, c))
            for lang, val in rec["desc"]:
                desc.append((cid, ORIGIN, ORIGIN, lang, val))
            for url, t in rec["ref"]:
                ref.append((cid, ORIGIN, ORIGIN, url, t))
            n += 1
            if (i + 1) % BATCH == 0:
                flush(cur)
        flush(cur)

    conn.close()
    return n


def _delete_scope(conn, cve_ids):
    with conn.cursor() as cur:
        for t in _INFO_TABLES:
            if cve_ids is None:
                cur.execute(f"DELETE FROM {t} WHERE origin = %s", (ORIGIN,))
            else:
                cur.execute(f"DELETE FROM {t} WHERE origin = %s AND cve_id = ANY(%s)", (ORIGIN, cve_ids))
    conn.commit()


def run(conn, dirs: dict) -> int:
    base = Path(dirs["nvd"])
    repo = base / "repo"
    if not repo.exists():
        print("  nvd: repo not found — run `sync nvd` first")
        return 0

    state = base / ".ingest_head"
    current = head(repo)
    last = state.read_text().strip() if state.exists() else None

    if last and last != current:
        changed = git_changed_paths(repo, last)
        files = [repo / p for p in changed
                 if p.endswith(".json") and "CVE-" in p and (repo / p).exists()]
        scope = [c for c in (normalize(Path(p).stem) for p in files) if c]
        print(f"  nvd: {len(files):,} changed records since {last[:8]}")
        _delete_scope(conn, scope)
    elif last == current:
        print(f"  nvd: already at {current[:8]} — nothing to ingest")
        return 0
    else:
        files = sorted(repo.rglob("CVE-*.json"))
        print(f"  nvd: first import — {len(files):,} records")
        _delete_scope(conn, None)

    if not files:
        if current:
            state.write_text(current)
        return 0

    dsn = os.environ["POSTGRES_DSN"]
    workers = min(N_WORKERS, len(files))
    size = (len(files) + workers - 1) // workers
    chunks = [(files[i:i + size], dsn) for i in range(0, len(files), size)]

    total = 0
    with mp.Pool(workers) as pool:
        for n in pool.imap_unordered(_import_chunk, chunks):
            total += n
            print(f"  nvd: {total:,}/{len(files):,}", flush=True)

    if current:
        state.write_text(current)
    print(f"  nvd: {total:,} records")
    return total
