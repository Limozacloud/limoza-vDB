"""Ingest Alpine Linux secdb data."""
from ingest import json_compat as json
from pathlib import Path

from ingest.db import ingest_files
from ingest.incremental import ImportState
from ingest.alpine.transform import transform_file


def _transform(f: Path):
    data = json.loads(f.read_bytes())
    return list(transform_file(data))


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["alpine_secdb"])
    if not base.exists():
        print(f"  Alpine secdb: {base} not found — run `sync alpine` first")
        return

    state = ImportState(base / ".import_state.json", base)

    all_files = sorted(f for f in base.rglob("*.json") if f.name != "checkpoint.json")
    files = all_files if cve_filter else state.changed(all_files)
    print(f"  Alpine secdb: {len(files)} changed of {len(all_files)} files")

    total, skipped, errors = ingest_files(conn, files, _transform,
        label="Alpine secdb", cve_filter=cve_filter, state=state if not cve_filter else None)
    print(f"  Alpine secdb: {total:,} upserted · {skipped} skipped · {errors} errors")
