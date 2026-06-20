"""OSV package ecosystem importer."""
from ingest import json_compat as json
import multiprocessing as mp
from pathlib import Path

from ingest.db import ingest_files
from ingest.incremental import ImportState
from ingest.osv.sync import PKG_ECOSYSTEMS, _eco_dir
from ingest.osv.transform import transform

N_WORKERS = mp.cpu_count()


def _transform_file(f: Path):
    return transform(json.loads(f.read_bytes()))


def ingest(conn, dirs: dict, cve_filter: str | None = None) -> None:
    base = Path(dirs["osv"])

    index_path = base / "osv_index.json"
    if not index_path.exists():
        print("  OSV: no index — run `sync osv` first")
        return

    index: dict[str, list[str]] = json.loads(index_path.read_bytes())

    # Build set of files to process
    if cve_filter:
        rel_paths = index.get(cve_filter, [])
        files = [base / p for p in rel_paths]
        # Only keep files from package ecosystem dirs
        pkg_eco_dirs = {_eco_dir(base, eco) for eco in PKG_ECOSYSTEMS}
        files = [f for f in files if any(f.is_relative_to(d) for d in pkg_eco_dirs)]
        print(f"  OSV: filter {cve_filter} → {len(files)} pkg-ecosystem files")
    else:
        state = ImportState(base / ".import_state.json", base)
        all_files = []
        for eco in PKG_ECOSYSTEMS:
            eco_dir = _eco_dir(base, eco)
            if eco_dir.exists():
                all_files.extend(eco_dir.glob("*.json"))
        files = state.changed(all_files)
        print(f"  OSV: {len(files)} changed of {len(all_files)} files")

    total, skipped, errors = ingest_files(
        conn,
        files,
        _transform_file,
        label="OSV",
        cve_filter=cve_filter,
        n_workers=N_WORKERS if not cve_filter else 1,
        state=state if not cve_filter else None,
    )
    print(f"  OSV: {total} upserted · {skipped} skipped · {errors} errors")
