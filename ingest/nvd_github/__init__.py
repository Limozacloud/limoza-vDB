"""Import NVD CVE data from the GitHub JSON mirror — incrementally via _state.csv.

The mirror's `_state.csv` carries a per-CVE `sha256` (content hash of the CVE file).
We keep the snapshot of hashes from the last successful import in
`_state.imported.csv` and re-import only the CVEs whose sha256 changed (or are new).
A CVE that errors out is left out of the snapshot, so it retries on the next run.

Per-CVE files are the raw NVD CVE object — identical to what the API-based `nvd`
sync stored — so we reuse the existing NVD transform unchanged.
"""
import csv
from pathlib import Path

from ingest.db import upsert_lve_record
from ingest.nvd.transform import parse, transform


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
        print(f"  NVD-GitHub: {len(targets)} changed/new of {len(current)} CVEs")
    else:
        targets = list(current)
        print(f"  NVD-GitHub: first import — {len(targets)} CVEs")

    total = errors = missing = 0
    done: dict = {}  # cve -> sha256 successfully imported this run

    with conn.cursor() as cur:
        for i, cve in enumerate(targets):
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
                done[cve] = current[cve]
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                errors += 1
                if errors <= 5:
                    print(f"  Error {cve}: {e}")

            if not cve_filter and (i + 1) % 10_000 == 0:
                conn.commit()
                print(f"  {i+1}/{len(targets)} ({total} CVEs)")

    conn.commit()

    msg = f"  NVD-GitHub: {total} CVEs ingested · {errors} errors"
    if missing:
        msg += f" · {missing} missing files"
    print(msg)

    # Advance the import manifest: carry prev forward, overwrite with this run's
    # successes. Errored/missing CVEs keep their old hash and retry next time.
    if not cve_filter:
        prev.update(done)
        _write_snapshot(snapshot, prev)
        print(f"  NVD-GitHub: import manifest updated ({len(prev)} CVEs tracked)")
