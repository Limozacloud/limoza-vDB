from pathlib import Path
from ingest.db import bulk_update_lve_cve
from ingest.cisa_ssvc.transform import parse, _EXPLOITATION_MAP, _AUTOMATABLE_MAP, _IMPACT_MAP, _norm


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    index_path = Path(dirs["cisa_ssvc"]) / "ssvc_index.json"
    if not index_path.exists():
        print(f"  CISA SSVC: {index_path} not found — run `sync cisa_ssvc` first")
        return

    data = parse(index_path.read_bytes())
    if cve_filter:
        data = {cve_filter: data[cve_filter]} if cve_filter in data else {}
        print(f"  CISA SSVC: filter {cve_filter}")
    else:
        print(f"  CISA SSVC: {len(data)} CVEs")

    rows = []
    for cve_id, entry in data.items():
        exploitation = _norm(entry.get("ssvc_exploitation", ""), _EXPLOITATION_MAP)
        if not exploitation:
            continue
        rows.append({
            "cve_id":                cve_id,
            "ssvc_exploitation":     exploitation,
            "ssvc_automatable":      _norm(entry.get("ssvc_automatable", ""), _AUTOMATABLE_MAP),
            "ssvc_technical_impact": _norm(entry.get("ssvc_technical_impact", ""), _IMPACT_MAP),
        })

    count = bulk_update_lve_cve(conn, rows, ["ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact"])
    print(f"  CISA SSVC: {count} entries updated")
