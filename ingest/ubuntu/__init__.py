"""Ingest Ubuntu CVE data from canonical/ubuntu-security-notices."""
import functools
from ingest import json_compat as json
import multiprocessing as mp
from pathlib import Path

from ingest.db import ingest_files
from ingest.incremental import ImportState
from ingest.ubuntu.transform import transform

N_WORKERS = mp.cpu_count()


def _load_usn_map(base: Path) -> tuple:
    """Build {usn_id: {title, summary, timestamp}} and {cve_id: [usn_id, ...]} lookup."""
    usn_meta:   dict = {}
    cve_to_usn: dict = {}

    usn_path = base / "usn"
    if not usn_path.exists():
        print("  Ubuntu USN: no usn/ directory found — run `sync ubuntu` first")
        return {}, {}

    for f in usn_path.glob("*.json"):
        try:
            d = json.loads(f.read_bytes())
        except Exception:
            continue
        usn_id  = d.get("id", f.stem)
        usn_meta[usn_id] = {
            "title":     (d.get("title") or "").strip(),
            "summary":   (d.get("isummary") or d.get("summary") or "").strip(),
            "timestamp": d.get("timestamp"),
        }
        for cve_id in (d.get("cves") or []):
            if cve_id.startswith("CVE-"):
                cve_to_usn.setdefault(cve_id, []).append(usn_id)

    print(f"  Ubuntu USN: {len(usn_meta)} advisories, {len(cve_to_usn)} CVEs mapped")
    return usn_meta, cve_to_usn


def _build_osv_index(base: Path) -> dict:
    """Build {cve_id: path} lookup from osv/cve/ — files named UBUNTU-CVE-YYYY-NNNN.json."""
    osv_base = base / "osv" / "cve"
    if not osv_base.exists():
        return {}
    return {f.stem[len("UBUNTU-"):]: f for f in osv_base.rglob("UBUNTU-CVE-*.json")}


def _transform_file(f: Path, *, usn_meta, cve_to_usn, osv_index):
    """Module-level so functools.partial of this is picklable for multiprocessing."""
    cve_id   = f.stem.upper()
    vex_data = json.loads(f.read_bytes())
    osv_data = None
    osv_path = osv_index.get(cve_id)
    if osv_path:
        try:
            osv_data = json.loads(osv_path.read_bytes())
        except Exception:
            pass
    return transform(cve_id, vex_data, usn_meta, cve_to_usn, osv_data)


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["ubuntu_usn"])
    if not base.exists():
        print(f"  Ubuntu: {base} not found — run `sync ubuntu` first")
        return

    usn_meta, cve_to_usn = _load_usn_map(base)
    osv_index             = _build_osv_index(base)

    vex_base = base / "vex" / "cve"
    if not vex_base.exists():
        print(f"  Ubuntu VEX: {vex_base} not found — run `sync ubuntu` first")
        return

    state = ImportState(base / ".import_state.json", base)

    if cve_filter:
        fname = cve_filter.upper() + ".json"
        found = next(vex_base.rglob(fname), None)
        files = [found] if found else []
        print(f"  Ubuntu VEX: filter {cve_filter} → {len(files)} files")
    else:
        all_files = sorted(vex_base.rglob("CVE-*.json"))
        files = state.changed(all_files)
        print(f"  Ubuntu VEX: {len(files):,} changed of {len(all_files):,} CVE files")

    fn = functools.partial(_transform_file,
                           usn_meta=usn_meta, cve_to_usn=cve_to_usn, osv_index=osv_index)
    total, skipped, errors = ingest_files(conn, files, fn,
        label="Ubuntu VEX", n_workers=N_WORKERS, cve_filter=cve_filter, state=state)
    print(f"  Ubuntu VEX: {total:,} upserted · {skipped} skipped · {errors} errors")
