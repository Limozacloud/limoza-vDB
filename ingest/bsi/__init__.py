from ingest import json_compat as json
from pathlib import Path

from ingest.db import ingest_records
from ingest.bsi.transform import transform


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    bsi_dir    = Path(dirs["bsi"])
    index_path = bsi_dir / "bsi_index.json"
    csaf_dir   = bsi_dir / "csaf"

    if not index_path.exists():
        print(f"  BSI: {index_path} not found — run `sync bsi` first")
        return

    idx      = json.loads(index_path.read_bytes())
    has_csaf = csaf_dir.exists() and any(csaf_dir.iterdir())

    if cve_filter:
        idx = {cve_filter: idx[cve_filter]} if cve_filter in idx else {}
        print(f"  BSI: filter {cve_filter}")
    else:
        print(f"  BSI: {len(idx)} CVEs" + (" (with CSAF)" if has_csaf else ""))

    def _records():
        for cve_id, entry in idx.items():
            wid_id = entry.get("wid_id", "")
            if wid_id:
                yield transform(cve_id, wid_id, entry.get("wid_url", ""),
                                csaf_dir if has_csaf else None)

    total, _, errors = ingest_records(conn, _records(), label="BSI", cve_filter=cve_filter)
    print(f"  BSI: {total:,} upserted · {errors} errors")
