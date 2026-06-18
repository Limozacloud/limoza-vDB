"""OSV package ecosystem importer."""
import json
from pathlib import Path

from ingest.db import upsert_lve_record
from ingest.osv.sync import PKG_ECOSYSTEMS, _eco_dir
from ingest.osv.transform import transform


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
        files = []
        for eco in PKG_ECOSYSTEMS:
            eco_dir = _eco_dir(base, eco)
            if eco_dir.exists():
                files.extend(eco_dir.glob("*.json"))

    upserted = skipped = errors = 0
    with conn.cursor() as cur:
        for fpath in files:
            try:
                data = json.loads(fpath.read_bytes())
                rec  = transform(data)
                if rec is None:
                    skipped += 1
                    continue
                upsert_lve_record(cur, rec)
                upserted += 1
            except Exception as e:
                errors += 1
                if errors <= 5:
                    print(f"  OSV error {fpath.name}: {e}")
        conn.commit()

    print(f"  OSV: {upserted} upserted · {skipped} skipped · {errors} errors")
