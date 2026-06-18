"""Ingest RedHat CVE data from local CSAF VEX and Advisory caches."""
import json
from pathlib import Path

from ingest.db import upsert_lve_record
from ingest.redhat.transform import transform, transform_advisory


def ingest(conn, dirs: dict, cve_filter: str = None) -> None:
    base = Path(dirs["redhat"])
    vex_base = base / "vex"
    adv_base = base / "advisories"

    if not vex_base.exists():
        print(f"  RedHat: {vex_base} not found — run `sync redhat` first")
        return

    # ── VEX import ────────────────────────────────────────────────────────────
    if cve_filter:
        year  = cve_filter.split("-")[1]
        fname = cve_filter.lower() + ".json"
        f     = vex_base / year / fname
        vex_files = [f] if f.exists() else []
        print(f"  RedHat VEX: filter {cve_filter} → {len(vex_files)} files")
    else:
        vex_files = sorted(vex_base.rglob("cve-*.json"))
        print(f"  RedHat VEX: {len(vex_files)} CVE files")

    total = skipped = errors = 0

    with conn.cursor() as cur:
        for i, f in enumerate(vex_files):
            try:
                cur.execute("SAVEPOINT sp")
                data   = json.loads(f.read_bytes())
                record = transform(data)

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
                print(f"  {i+1}/{len(vex_files)}")

    conn.commit()
    print(f"  RedHat VEX: {total} upserted · {skipped} skipped · {errors} errors")

    # ── Advisory import ───────────────────────────────────────────────────────
    if not adv_base.exists():
        print(f"  RedHat advisories: {adv_base} not found — skipping")
        return

    if cve_filter:
        # resolve RHSA IDs already imported from VEX for this CVE
        with conn.cursor() as cur:
            cur.execute("""
                SELECT a.advisory_id FROM lve_advisories a
                JOIN lve ON lve.lve_id = a.lve_id
                WHERE %s = ANY(lve.aliases)
            """, (cve_filter,))
            rhsa_ids = [row[0] for row in cur.fetchall()]
        adv_files = []
        for rhsa_id in rhsa_ids:
            # RHSA-2022:5726 → advisories/2022/rhsa-2022_5726.json
            fname = rhsa_id.lower().replace(":", "_")   # rhsa-2022_5726
            year  = fname.split("-")[1].split("_")[0]   # 2022
            p = adv_base / year / f"{fname}.json"
            if p.exists():
                adv_files.append(p)
    else:
        adv_files = sorted(adv_base.rglob("rhsa-*.json"))

    print(f"  RedHat advisories: {len(adv_files)} files")
    adv_total = adv_errors = 0

    with conn.cursor() as cur:
        for i, f in enumerate(adv_files):
            try:
                cur.execute("SAVEPOINT sp")
                data    = json.loads(f.read_bytes())
                records = transform_advisory(data)

                for rec in records:
                    cve_id  = rec["cve_id"]
                    rhsa_id = rec["rhsa_id"]

                    # resolve lve_id from cve_id via aliases
                    cur.execute(
                        "SELECT lve_id FROM lve WHERE %s = ANY(aliases) LIMIT 1",
                        (cve_id,)
                    )
                    row = cur.fetchone()
                    if not row:
                        continue
                    lve_id = row[0]

                    # update advisory published/updated/vendor_data
                    vendor_data = {}
                    if rec.get("reboot_required"):
                        vendor_data["reboot_required"] = True
                    cur.execute("""
                        UPDATE lve_advisories
                        SET published   = COALESCE(%s, published),
                            updated     = COALESCE(%s, updated),
                            vendor_data = CASE
                                WHEN %s::jsonb IS NOT NULL
                                THEN COALESCE(vendor_data, '{}'::jsonb) || %s::jsonb
                                ELSE vendor_data
                            END
                        WHERE lve_id = %s AND advisory_id = %s
                    """, (rec["published"], rec["updated"],
                          json.dumps(vendor_data) if vendor_data else None,
                          json.dumps(vendor_data) if vendor_data else None,
                          lve_id, rhsa_id))

                    # add advisory-level title
                    if rec["title"]:
                        cur.execute("""
                            INSERT INTO lve_titles (lve_id, value, source, advisory_ref)
                            VALUES (%s, %s, 'redhat', %s)
                            ON CONFLICT (lve_id, source, advisory_ref) DO UPDATE SET
                                value = EXCLUDED.value
                        """, (lve_id, rec["title"], rhsa_id))

                    # add advisory revision history
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
    print(f"  RedHat advisories: {adv_total} processed · {adv_errors} errors")
