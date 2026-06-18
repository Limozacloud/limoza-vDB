"""Ingest SUSE CVE data from local CSAF VEX and Advisory caches."""
import json
from pathlib import Path

from ingest.db import upsert_lve_record
from ingest.suse.transform import transform, transform_advisory


def _adv_slug(adv_id: str) -> str:
    return adv_id.lower().replace(":", "_")


def _load_adv_map(base: Path) -> dict:
    p = base / "adv_map.json"
    if p.exists():
        adv_map = json.loads(p.read_bytes())
        print(f"  SUSE: {len(adv_map)} CVEs in advisory map")
        return adv_map
    print("  SUSE: no advisory map found (run `sync suse` to build it)")
    return {}


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["suse_vex"])
    if not base.exists():
        print(f"  SUSE: {base} not found — run `sync suse` first")
        return

    adv_map = _load_adv_map(base)

    # ── VEX import ────────────────────────────────────────────────────────────
    if cve_filter:
        fname = cve_filter.lower() + ".json"
        found = next(base.rglob(fname), None)
        files = [found] if found else []
        print(f"  SUSE VEX: filter {cve_filter} → {len(files)} files")
    else:
        files = sorted(base.rglob("cve-*.json"))
        print(f"  SUSE VEX: {len(files)} CVE files")

    total = skipped = errors = 0

    with conn.cursor() as cur:
        for i, f in enumerate(files):
            try:
                cur.execute("SAVEPOINT sp")
                data   = json.loads(f.read_bytes())
                record = transform(data, adv_map)

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
    print(f"  SUSE VEX: {total} upserted · {skipped} skipped · {errors} errors")

    # ── Advisory import ───────────────────────────────────────────────────────
    adv_base = base / "advisories"
    if not adv_base.exists():
        print(f"  SUSE advisories: {adv_base} not found — skipping (run `sync suse` to populate)")
        return

    if cve_filter:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT a.advisory_id FROM lve_advisories a
                JOIN lve ON lve.lve_id = a.lve_id
                WHERE %s = ANY(lve.aliases)
            """, (cve_filter,))
            suse_adv_ids = [row[0] for row in cur.fetchall()]
        adv_files = []
        for adv_id in suse_adv_ids:
            p = adv_base / f"{_adv_slug(adv_id)}.json"
            if p.exists():
                adv_files.append(p)
    else:
        adv_files = sorted(adv_base.glob("*.json"))

    print(f"  SUSE advisories: {len(adv_files)} files")
    adv_total = adv_errors = 0

    with conn.cursor() as cur:
        for i, f in enumerate(adv_files):
            try:
                cur.execute("SAVEPOINT sp")
                data    = json.loads(f.read_bytes())
                records = transform_advisory(data)

                for rec in records:
                    cve_id = rec["cve_id"]
                    adv_id = rec["adv_id"]

                    cur.execute(
                        "SELECT lve_id FROM lve WHERE %s = ANY(aliases) LIMIT 1",
                        (cve_id,)
                    )
                    row = cur.fetchone()
                    if not row:
                        continue
                    lve_id = row[0]

                    cur.execute("""
                        UPDATE lve_advisories
                        SET published = COALESCE(%s, published),
                            updated   = COALESCE(%s, updated)
                        WHERE lve_id = %s AND advisory_id = %s
                    """, (rec["published"], rec["updated"], lve_id, adv_id))

                    if rec["title"]:
                        cur.execute("""
                            INSERT INTO lve_titles (lve_id, value, source, advisory_ref)
                            VALUES (%s, %s, 'suse', %s)
                            ON CONFLICT (lve_id, source, advisory_ref) DO UPDATE SET
                                value = EXCLUDED.value
                        """, (lve_id, rec["title"], adv_id))

                    for h in rec.get("history") or []:
                        cur.execute("""
                            INSERT INTO lve_history (lve_id, date, event, source, detail)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT DO NOTHING
                        """, (lve_id, h["date"], h["event"], h["source"], h["detail"]))

                adv_total += 1
                cur.execute("RELEASE SAVEPOINT sp")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                adv_errors += 1
                if adv_errors <= 5:
                    print(f"  Error {f.name}: {e}")

            if not cve_filter and (i + 1) % 2000 == 0:
                conn.commit()
                print(f"  advisories {i+1}/{len(adv_files)}")

    conn.commit()
    print(f"  SUSE advisories: {adv_total} processed · {adv_errors} errors")
