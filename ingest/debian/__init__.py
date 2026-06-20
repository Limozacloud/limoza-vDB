"""Ingest Debian Security Tracker data."""
from ingest import json_compat as json
from pathlib import Path

from ingest.db import ingest_records
from ingest.debian.transform import transform, parse_adv_list


def _load_adv_data(base: Path) -> tuple[dict, dict, dict]:
    adv_map:    dict = {}
    adv_dates:  dict = {}
    adv_titles: dict = {}
    for fname in ("dsa_list.txt", "dla_list.txt"):
        p = base / fname
        if p.exists():
            m, d, t = parse_adv_list(p.read_text(encoding="utf-8", errors="replace"))
            for k, v in m.items():
                adv_map.setdefault(k, [])
                for aid in v:
                    if aid not in adv_map[k]:
                        adv_map[k].append(aid)
            adv_dates.update(d)
            adv_titles.update(t)
    adv_count = sum(len(v) for v in adv_map.values())
    print(f"  Debian tracker: {adv_count} DSA/DLA mappings, {len(adv_dates)} dates, {len(adv_titles)} titles loaded")
    return adv_map, adv_dates, adv_titles


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base      = Path(dirs["debian_tracker"])
    data_path = base / "data.json"
    if not data_path.exists():
        print(f"  Debian tracker: {data_path} not found — run `sync debian` first")
        return

    adv_map, adv_dates, adv_titles = _load_adv_data(base)

    print("  Debian tracker: loading data.json...")
    data = json.loads(data_path.read_bytes())

    total, skipped, errors = ingest_records(
        conn,
        transform(data, adv_map, adv_dates, adv_titles),
        label="Debian tracker",
        cve_filter=cve_filter,
    )
    print(f"  Debian tracker: {total} upserted · {skipped} skipped · {errors} errors")
