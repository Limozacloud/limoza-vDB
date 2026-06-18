"""Ingest Ubuntu CVE data from canonical/ubuntu-security-notices."""
import json
from pathlib import Path

from ingest.db import upsert_lve_record
from ingest.ubuntu.transform import transform


def _load_usn_map(base: Path) -> tuple[dict, dict]:
    """Build {usn_id: {title, summary, timestamp}} and {cve_id: [usn_id, ...]} lookup."""
    usn_meta:   dict[str, dict] = {}
    cve_to_usn: dict[str, list] = {}

    usn_path = base / "usn"
    if not usn_path.exists():
        print("  Ubuntu USN: no usn/ directory found — run `sync ubuntu` first")
        return {}, {}

    for f in usn_path.glob("*.json"):
        try:
            d = json.loads(f.read_bytes())
        except Exception:
            continue
        usn_id    = d.get("id", f.stem)
        title     = (d.get("title") or "").strip()
        summary   = (d.get("isummary") or d.get("summary") or "").strip()
        timestamp = d.get("timestamp")

        usn_meta[usn_id] = {"title": title, "summary": summary, "timestamp": timestamp}

        for cve_id in (d.get("cves") or []):
            if cve_id.startswith("CVE-"):
                cve_to_usn.setdefault(cve_id, []).append(usn_id)

    print(f"  Ubuntu USN: {len(usn_meta)} advisories, {len(cve_to_usn)} CVEs mapped")
    return usn_meta, cve_to_usn


def _build_osv_index(base: Path) -> dict[str, Path]:
    """Build {cve_id: path} lookup from osv/cve/ — files named UBUNTU-CVE-YYYY-NNNN.json."""
    osv_base = base / "osv" / "cve"
    if not osv_base.exists():
        return {}
    index = {}
    for f in osv_base.rglob("UBUNTU-CVE-*.json"):
        cve_id = f.stem[len("UBUNTU-"):]   # "UBUNTU-CVE-2024-1234" → "CVE-2024-1234"
        index[cve_id] = f
    return index


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

    if cve_filter:
        fname = cve_filter.upper() + ".json"
        found = next(vex_base.rglob(fname), None)
        files = [found] if found else []
        print(f"  Ubuntu VEX: filter {cve_filter} → {len(files)} files")
    else:
        files = sorted(vex_base.rglob("CVE-*.json"))
        print(f"  Ubuntu VEX: {len(files)} CVE files")

    total = skipped = errors = 0

    with conn.cursor() as cur:
        for i, f in enumerate(files):
            cve_id = f.stem.upper()
            try:
                cur.execute("SAVEPOINT sp")
                vex_data = json.loads(f.read_bytes())

                osv_data = None
                osv_path = osv_index.get(cve_id)
                if osv_path:
                    try:
                        osv_data = json.loads(osv_path.read_bytes())
                    except Exception:
                        pass

                record = transform(cve_id, vex_data, usn_meta, cve_to_usn, osv_data)

                if record is None:
                    skipped += 1
                    cur.execute("RELEASE SAVEPOINT sp")
                    continue

                upsert_lve_record(cur, record)
                total += 1
                cur.execute("RELEASE SAVEPOINT sp")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                errors += 1
                if errors <= 5:
                    print(f"  Error {f.name}: {e}")

            if not cve_filter and (i + 1) % 5000 == 0:
                conn.commit()
                print(f"  {i+1}/{len(files)}")

    conn.commit()
    print(f"  Ubuntu VEX: {total} records upserted · {skipped} skipped · {errors} errors")
