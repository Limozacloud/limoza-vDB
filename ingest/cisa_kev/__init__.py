from pathlib import Path
from ingest.db import bulk_update_lve_cve
from ingest.cisa_kev.transform import parse


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    index_path = Path(dirs["cisa_kev"]) / "kev_index.json"
    if not index_path.exists():
        print(f"  CISA KEV: {index_path} not found — run `sync cisa_kev` first")
        return

    data = parse(index_path.read_bytes())
    if cve_filter:
        data = {cve_filter: data[cve_filter]} if cve_filter in data else {}
        print(f"  CISA KEV: filter {cve_filter}")
    else:
        print(f"  CISA KEV: {len(data)} entries")

    rows = []
    for cve_id, entry in data.items():
        known_ransomware = entry.get("known_ransomware")
        if isinstance(known_ransomware, str):
            known_ransomware = known_ransomware.strip().lower() == "known"
        rows.append({
            "cve_id":               cve_id,
            "kev_date_added":       entry.get("date_added") or None,
            "kev_due_date":         entry.get("due_date") or None,
            "kev_known_ransomware": known_ransomware,
            "kev_required_action":  entry.get("required_action") or None,
        })

    count = bulk_update_lve_cve(conn, rows, ["kev_date_added", "kev_due_date", "kev_known_ransomware", "kev_required_action"])
    print(f"  CISA KEV: {count} entries updated")
