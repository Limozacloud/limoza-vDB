"""Import NVD CVE data from the GitHub JSON mirror — incrementally via _state.csv.

The mirror's `_state.csv` carries a per-CVE `sha256` (content hash of the CVE file).
We keep the snapshot of hashes from the last successful import in
`_state.imported.csv` and re-import only the CVEs whose sha256 changed (or are new).
A CVE that errors out is left out of the snapshot, so it retries on the next run.

Per-CVE files are the raw NVD CVE object — identical to what the API-based `nvd`
sync stored — so we reuse the existing NVD transform unchanged.

Parallel import: targets are split into N_WORKERS chunks; each worker opens its own
DB connection and commits every COMMIT_EVERY CVEs. Workers are independent (each CVE
ID appears exactly once in the target list) so there are no write conflicts.
"""
import csv
import multiprocessing as mp
import os
from pathlib import Path

from ingest.nvd.transform import parse, transform

COMMIT_EVERY = 2_000
N_WORKERS    = 8


def _load_state(path: Path) -> dict:
    """Return {cve_id: sha256} from a CSV that has at least `cve` and `sha256` columns."""
    state: dict = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            state[row["cve"]] = row["sha256"]
    return state


def _path_for(base: Path, cve: str) -> Path:
    # CVE-2024-3094 -> CVE-2024/CVE-2024-30xx/CVE-2024-3094.json  (last 2 digits bucketed)
    _, year, num = cve.split("-")
    bucket = f"CVE-{year}-{num[:-2]}xx"
    return base / f"CVE-{year}" / bucket / f"{cve}.json"


def _write_snapshot(path: Path, state: dict) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve", "sha256"])
        for cve, sha in state.items():
            w.writerow([cve, sha])


def _import_chunk(args):
    """Worker process: import one chunk of CVEs.

    Returns (done_dict, total, errors, missing).
    Imports inside the function to work correctly under both fork and spawn.
    """
    chunk, base_str, dsn, current_hashes = args

    import psycopg2
    from ingest.db import upsert_lve_record

    base  = Path(base_str)
    conn  = psycopg2.connect(dsn)
    total = errors = missing = 0
    done  = {}

    with conn.cursor() as cur:
        for i, cve in enumerate(chunk):
            f = _path_for(base, cve)
            if not f.exists():
                missing += 1
                continue
            try:
                cur.execute("SAVEPOINT sp")
                for record in transform(parse(f.read_bytes())):
                    upsert_lve_record(cur, record)
                    total += 1
                cur.execute("RELEASE SAVEPOINT sp")
                done[cve] = current_hashes[cve]
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                errors += 1

            if (i + 1) % COMMIT_EVERY == 0:
                conn.commit()

    conn.commit()
    conn.close()
    return done, total, errors, missing


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base      = Path(dirs["nvd_github"])
    state_csv = base / "_state.csv"
    if not state_csv.exists():
        print(f"  NVD-GitHub: {state_csv} not found — run `sync nvd-github` first")
        return

    current  = _load_state(state_csv)
    snapshot = base / "_state.imported.csv"
    prev     = _load_state(snapshot) if snapshot.exists() else {}

    if cve_filter:
        targets = [cve_filter] if cve_filter in current else []
        print(f"  NVD-GitHub: filter {cve_filter} → {len(targets)} file(s)")
    elif prev:
        targets = [c for c, h in current.items() if prev.get(c) != h]
        print(f"  NVD-GitHub: {len(targets):,} changed/new of {len(current):,} CVEs")
    else:
        targets = list(current)
        print(f"  NVD-GitHub: first import — {len(targets):,} CVEs")

    if not targets:
        print("  NVD-GitHub: nothing to import")
        return

    # Single-CVE filter: use the passed connection directly, no multiprocessing
    if cve_filter:
        f = _path_for(base, targets[0])
        if not f.exists():
            print(f"  NVD-GitHub: file not found for {cve_filter}")
            return
        with conn.cursor() as cur:
            cur.execute("SAVEPOINT sp")
            try:
                for record in transform(parse(f.read_bytes())):
                    upsert_lve_record(cur, record)
                cur.execute("RELEASE SAVEPOINT sp")
                print(f"  NVD-GitHub: imported {cve_filter}")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                print(f"  Error {cve_filter}: {e}")
        conn.commit()
        return

    # Parallel import
    dsn       = os.environ["POSTGRES_DSN"]
    n_workers = min(N_WORKERS, mp.cpu_count(), len(targets))
    chunk_size = (len(targets) + n_workers - 1) // n_workers
    chunks     = [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]

    print(f"  NVD-GitHub: {n_workers} workers · ~{chunk_size:,} CVEs each · commit every {COMMIT_EVERY:,}")

    worker_args = [(chunk, str(base), dsn, current) for chunk in chunks]

    with mp.Pool(n_workers) as pool:
        results = pool.map(_import_chunk, worker_args)

    total = errors = missing = 0
    done  = {}
    for worker_done, worker_total, worker_errors, worker_missing in results:
        total   += worker_total
        errors  += worker_errors
        missing += worker_missing
        done.update(worker_done)

    msg = f"  NVD-GitHub: {total:,} CVEs ingested · {errors} errors"
    if missing:
        msg += f" · {missing} missing files"
    print(msg)

    prev.update(done)
    _write_snapshot(snapshot, prev)
    print(f"  NVD-GitHub: import manifest updated ({len(prev):,} CVEs tracked)")
