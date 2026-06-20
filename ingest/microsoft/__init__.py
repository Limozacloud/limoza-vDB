import multiprocessing as mp
from pathlib import Path

from ingest.db import ingest_files
from ingest.incremental import ImportState
from ingest.microsoft.transform import parse, transform
from ingest.cpe import validate as _cpe_validate

N_WORKERS = min(mp.cpu_count(), 4)


def _transform_file(f: Path):
    return transform(parse(f.read_bytes()))


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    _cpe_validate.load(dirs.get("cpe", ""))
    base = Path(dirs["msrc"]) / "cvrf"
    if not base.exists():
        print(f"  Microsoft: data not found at {base} — run `sync microsoft` first")
        return

    state = ImportState(base / ".import_state.json", base)

    all_files = sorted(base.glob("*.json"))
    files = all_files if cve_filter else state.changed(all_files)
    print(f"  Microsoft: {len(files)} CVRF files" + (f" (filter: {cve_filter})" if cve_filter else f" of {len(all_files)}"))

    total, skipped, errors = ingest_files(conn, files, _transform_file,
        label="Microsoft", cve_filter=cve_filter, n_workers=N_WORKERS, state=state if not cve_filter else None)
    print(f"  Microsoft: {total:,} records upserted · {errors} errors")
