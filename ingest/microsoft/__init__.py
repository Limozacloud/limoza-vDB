from pathlib import Path

from ingest.db import ingest_files
from ingest.microsoft.transform import parse, transform
from ingest.cpe import validate as _cpe_validate

N_WORKERS = 4


def _transform_file(f: Path):
    return transform(parse(f.read_bytes()))


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    _cpe_validate.load(dirs.get("cpe", ""))
    base = Path(dirs["msrc"]) / "cvrf"
    if not base.exists():
        print(f"  Microsoft: data not found at {base} — run `sync microsoft` first")
        return

    files = sorted(base.glob("*.json"))
    print(f"  Microsoft: {len(files)} CVRF files" + (f" (filter: {cve_filter})" if cve_filter else ""))

    total, skipped, errors = ingest_files(conn, files, _transform_file,
        label="Microsoft", cve_filter=cve_filter, n_workers=N_WORKERS)
    print(f"  Microsoft: {total:,} records upserted · {errors} errors")
