from ingest import json_compat as json
import multiprocessing as mp
from pathlib import Path

from ingest.db import ingest_files
from ingest.incremental import ImportState
from ingest.ghsa.transform import transform

N_WORKERS = mp.cpu_count()


def _transform_file(f: Path):
    records = transform(json.loads(f.read_bytes()))
    return records if records else None


def _walk(base: Path):
    for subdir in ("github-reviewed", "unreviewed"):
        d = base / "advisories" / subdir
        if d.exists():
            yield from d.rglob("GHSA-*.json")


def _build_index(base: Path) -> dict:
    idx: dict[str, list] = {}
    for f in _walk(base):
        try:
            raw = f.read_bytes()
            if b"CVE-" not in raw:
                continue
            data = json.loads(raw)
            for alias in (data.get("aliases") or []):
                if isinstance(alias, str) and alias.startswith("CVE-"):
                    idx.setdefault(alias, []).append(str(f.relative_to(base)))
        except Exception:
            pass
    out = base / "cve_index.json"
    out.write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    return idx


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["ghsa"])
    if not base.exists():
        print(f"  GHSA: {base} not found — run `sync ghsa` first")
        return

    if cve_filter:
        index_path = base / "cve_index.json"
        if index_path.exists():
            idx = json.loads(index_path.read_bytes())
        else:
            print("  GHSA: building CVE index (~2 min on first run)...")
            idx = _build_index(base)
        files = [base / p for p in idx.get(cve_filter, [])]
        print(f"  GHSA: filter {cve_filter} → {len(files)} advisories")
    else:
        state = ImportState(base / ".import_state.json", base)
        all_files = list(_walk(base))
        files = state.changed(all_files)
        print(f"  GHSA: {len(files)} changed of {len(all_files)} advisory files")

    total, skipped, errors = ingest_files(
        conn,
        files,
        _transform_file,
        label="GHSA",
        cve_filter=cve_filter,
        n_workers=N_WORKERS if not cve_filter else 1,
        state=state if not cve_filter else None,
    )
    print(f"  GHSA: {total} LVE records upserted · {skipped} skipped (no CVE alias or withdrawn)")
