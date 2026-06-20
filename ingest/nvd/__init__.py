"""Import NVD CVE data from the Limozacloud mirror — incrementally via _state.csv.

The mirror's _state.csv carries a per-CVE sha256 (content hash of the CVE file).
We keep a snapshot of hashes from the last successful import in _state.imported.csv
and re-import only CVEs whose sha256 changed or are new.
A CVE that errors out is left out of the snapshot so it retries on the next run.

Parallel import: targets are split into N_WORKERS chunks; each worker opens its own
DB connection and commits every COMMIT_EVERY CVEs.
"""
import csv
import multiprocessing as mp
import os
from pathlib import Path

from ingest.nvd.transform import parse, transform

COMMIT_EVERY = 2_000
N_WORKERS    = mp.cpu_count()


def _load_state(path: Path) -> dict:
    """Return {cve_id: sha256} from a CSV that has at least cve and sha256 columns."""
    state: dict = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            state[row["cve"]] = row["sha256"]
    return state


def _path_for(base: Path, cve: str) -> Path:
    _, year, num = cve.split("-")
    return base / "data" / f"CVE-{year}" / f"CVE-{year}-{num[:-2]}xx" / f"{cve}.json"


def _write_snapshot(path: Path, state: dict) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve", "sha256"])
        for cve, sha in state.items():
            w.writerow([cve, sha])


_PROGRESS_EVERY = 5_000


def _import_chunk(args):
    chunk, base_str, dsn, current_hashes, worker_id = args

    import psycopg2
    from ingest.db import RecordBatch

    base  = Path(base_str)
    conn  = psycopg2.connect(dsn)
    total = errors = missing = 0
    done  = {}
    batch      = RecordBatch()
    batch_cves = []

    with conn.cursor() as cur:
        for i, cve in enumerate(chunk):
            f = _path_for(base, cve)
            if not f.exists():
                missing += 1
                continue
            try:
                records = list(transform(parse(f.read_bytes())))
                for record in records:
                    batch.add(cur, record)
                batch_cves.append(cve)
                total += len(records)
            except Exception as e:
                errors += 1
                if errors <= 3:
                    print(f"  [w{worker_id}] Error {cve}: {e}", flush=True)

            if (i + 1) % COMMIT_EVERY == 0:
                try:
                    batch.flush(cur)
                    conn.commit()
                    for c in batch_cves:
                        done[c] = current_hashes[c]
                    batch_cves.clear()
                except Exception as e:
                    conn.rollback()
                    errors += len(batch_cves)
                    print(f"  [w{worker_id}] Flush error at {i+1:,}: {e}", flush=True)
                    batch._clear()
                    batch_cves.clear()

            if (i + 1) % _PROGRESS_EVERY == 0:
                print(f"  [w{worker_id}] {i+1:,}/{len(chunk):,}", flush=True)

        try:
            batch.flush(cur)
            conn.commit()
            for c in batch_cves:
                done[c] = current_hashes[c]
        except Exception as e:
            conn.rollback()
            errors += len(batch_cves)
            print(f"  [w{worker_id}] Final flush error: {e}", flush=True)

    conn.close()
    return done, total, errors, missing



def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base      = Path(dirs["nvd"])
    state_csv = base / "_state.csv"
    if not state_csv.exists():
        print(f"  NVD: {state_csv} not found — run `sync nvd` first")
        return

    current  = _load_state(state_csv)
    snapshot = base / "_state.imported.csv"
    prev     = _load_state(snapshot) if snapshot.exists() else {}

    if cve_filter:
        targets = [cve_filter] if cve_filter in current else []
        print(f"  NVD: filter {cve_filter} → {len(targets)} file(s)")
    elif prev:
        targets = [c for c, h in current.items() if prev.get(c) != h]
        print(f"  NVD: {len(targets):,} changed/new of {len(current):,} CVEs")
    else:
        targets = list(current)
        print(f"  NVD: first import — {len(targets):,} CVEs")

    if not targets:
        print("  NVD: nothing to import")
        return

    if cve_filter:
        from ingest.db import RecordBatch
        f = _path_for(base, targets[0])
        if not f.exists():
            print(f"  NVD: file not found for {cve_filter}")
            return
        batch = RecordBatch()
        with conn.cursor() as cur:
            cur.execute("SAVEPOINT sp")
            try:
                for record in transform(parse(f.read_bytes())):
                    batch.add(cur, record)
                batch.flush(cur)
                cur.execute("RELEASE SAVEPOINT sp")
                print(f"  NVD: imported {cve_filter}")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                print(f"  Error {cve_filter}: {e}")
        conn.commit()
        return

    dsn        = os.environ["POSTGRES_DSN"]
    n_workers  = min(N_WORKERS, mp.cpu_count(), len(targets))
    chunk_size = (len(targets) + n_workers - 1) // n_workers
    chunks     = [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]

    print(f"  NVD: {n_workers} workers · ~{chunk_size:,} CVEs each · commit every {COMMIT_EVERY:,}")

    worker_args = [(chunk, str(base), dsn, current, i) for i, chunk in enumerate(chunks)]

    total = errors = missing = 0
    done  = {}
    with mp.Pool(n_workers) as pool:
        for worker_done, worker_total, worker_errors, worker_missing in pool.imap_unordered(_import_chunk, worker_args):
            total   += worker_total
            errors  += worker_errors
            missing += worker_missing
            done.update(worker_done)
            print(f"  NVD: worker done · {total:,}/{len(targets):,} CVEs so far", flush=True)

    msg = f"  NVD: {total:,} CVEs ingested · {errors} errors"
    if missing:
        msg += f" · {missing} missing files"
    print(msg)

    prev.update(done)
    _write_snapshot(snapshot, prev)
    print(f"  NVD: import manifest updated ({len(prev):,} CVEs tracked)")
