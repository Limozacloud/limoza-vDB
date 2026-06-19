import datetime
from pathlib import Path
from ingest.db import bulk_update_lve_cve
from ingest.epss.transform import parse


def _parse_date(v):
    if not v:
        return None
    try:
        return datetime.date.fromisoformat(v)
    except (ValueError, TypeError):
        return None


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    index_path = Path(dirs["epss"]) / "epss.json"
    if not index_path.exists():
        print(f"  EPSS: {index_path} not found — run `sync epss` first")
        return

    data = parse(index_path.read_bytes())
    if cve_filter:
        data = {cve_filter: data[cve_filter]} if cve_filter in data else {}
        print(f"  EPSS: filter {cve_filter}")
    else:
        print(f"  EPSS: {len(data)} scores")

    rows = [
        {
            "cve_id":           cve_id,
            "epss_score":       float(v[0]),
            "epss_percentile":  float(v[1]),
            "epss_date":        _parse_date(v[2] if len(v) > 2 else None),
        }
        for cve_id, v in data.items() if len(v) >= 2
    ]
    count = bulk_update_lve_cve(conn, rows, ["epss_score", "epss_percentile", "epss_date"])
    print(f"  EPSS: {count} scores updated")
