"""Ingest Debian Security Tracker data."""
import json
from pathlib import Path

from ingest.db import upsert_lve_record
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

    total = skipped = errors = 0

    with conn.cursor() as cur:
        for i, record in enumerate(transform(data, adv_map, adv_dates, adv_titles)):
            cve_id = record["cve"]["cve_id"]
            if cve_filter and cve_id != cve_filter.upper():
                skipped += 1
                continue
            try:
                cur.execute("SAVEPOINT sp")
                upsert_lve_record(cur, record)
                total += 1
                cur.execute("RELEASE SAVEPOINT sp")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                errors += 1
                if errors <= 5:
                    print(f"  Error {cve_id}: {e}")

            if not cve_filter and (i + 1) % 10000 == 0:
                conn.commit()
                print(f"  {i + 1} records...")

    conn.commit()
    print(f"  Debian tracker: {total} upserted · {skipped} skipped · {errors} errors")
