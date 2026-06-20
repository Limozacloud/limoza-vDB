"""Ingest RedHat CVE data from local CSAF VEX and Advisory caches."""
from ingest import json_compat as json
import multiprocessing as mp
from pathlib import Path

from ingest.db import ingest_files
from ingest.incremental import ImportState
from ingest.redhat.transform import transform, transform_advisory
from psycopg2.extras import execute_values

N_WORKERS = mp.cpu_count()


def _transform_vex_file(f: Path):
    """Module-level so it can be used with multiprocessing."""
    data = json.loads(f.read_bytes())
    return transform(data)


def ingest(conn, dirs: dict, cve_filter: str = None, full: bool = False) -> None:
    base     = Path(dirs["redhat"])
    vex_base = base / "vex"
    adv_base = base / "advisories"

    if not vex_base.exists():
        print(f"  RedHat: {vex_base} not found — run `sync redhat` first")
        return

    state = ImportState(base / ".import_state.json", base)

    # ── VEX import ────────────────────────────────────────────────────────────
    if cve_filter:
        year  = cve_filter.split("-")[1]
        fname = cve_filter.lower() + ".json"
        f     = vex_base / year / fname
        vex_files = [f] if f.exists() else []
        print(f"  RedHat VEX: filter {cve_filter} → {len(vex_files)} files")
    else:
        all_vex   = sorted(vex_base.rglob("cve-*.json"))
        vex_files = state.changed(all_vex, full=full)
        print(f"  RedHat VEX: {len(vex_files):,} changed of {len(all_vex):,} CVE files")

    total, skipped, errors = ingest_files(conn, vex_files, _transform_vex_file,
        label="RedHat VEX", state=state, cve_filter=cve_filter,
        n_workers=N_WORKERS if not cve_filter else 1)
    print(f"  RedHat VEX: {total:,} upserted · {skipped} skipped · {errors} errors")

    # ── Advisory import ───────────────────────────────────────────────────────
    if not adv_base.exists():
        print(f"  RedHat advisories: {adv_base} not found — skipping")
        return

    if cve_filter:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT a.advisory_id FROM lve_advisories a
                JOIN lve ON lve.lve_id = a.lve_id
                WHERE %s = ANY(lve.aliases)
            """, (cve_filter,))
            rhsa_ids = [row[0] for row in cur.fetchall()]
        adv_files = []
        for rhsa_id in rhsa_ids:
            fname = rhsa_id.lower().replace(":", "_")
            year  = fname.split("-")[1].split("_")[0]
            p = adv_base / year / f"{fname}.json"
            if p.exists():
                adv_files.append(p)
        print(f"  RedHat advisories: {len(adv_files)} files")
    else:
        all_adv   = sorted(adv_base.rglob("rhsa-*.json"))
        adv_files = state.changed(all_adv, full=full)
        print(f"  RedHat advisories: {len(adv_files):,} changed of {len(all_adv):,} files")

    # ── Parse all advisory files, then bulk-apply in 3 statements ────────────
    adv_total = adv_errors = 0
    all_records = []
    for f in adv_files:
        try:
            records = transform_advisory(json.loads(f.read_bytes()))
            all_records.extend(records)
            adv_total += 1
            if not cve_filter:
                state.mark(f)
        except Exception as e:
            adv_errors += 1
            if adv_errors <= 5:
                print(f"  Error {f.name}: {e}")

    if all_records:
        all_cve_ids = list({r["cve_id"] for r in all_records})
        with conn.cursor() as cur:
            # Bulk-resolve cve_id → lve_id
            cur.execute("""
                SELECT lve_id, alias FROM lve
                CROSS JOIN LATERAL unnest(aliases) AS t(alias)
                WHERE alias = ANY(%s)
            """, (all_cve_ids,))
            cve_to_lve = {row[1]: row[0] for row in cur.fetchall()}

            upd_rows     = []
            title_rows   = []
            history_rows = []
            for rec in all_records:
                lve_id = cve_to_lve.get(rec["cve_id"])
                if not lve_id:
                    continue
                vendor_data = json.dumps({"reboot_required": True}) if rec.get("reboot_required") else None
                upd_rows.append((rec["published"], rec["updated"], vendor_data, lve_id, rec["rhsa_id"]))
                if rec["title"]:
                    title_rows.append((lve_id, rec["title"], "redhat", rec["rhsa_id"]))
                for h in rec.get("history") or []:
                    history_rows.append((lve_id, h["date"], h["event"], h["source"], h.get("detail")))

            if upd_rows:
                execute_values(cur, """
                    UPDATE lve_advisories
                    SET published   = COALESCE(v.published::timestamptz, lve_advisories.published),
                        updated     = COALESCE(v.updated::timestamptz,   lve_advisories.updated),
                        vendor_data = CASE
                            WHEN v.vendor_data::jsonb IS NOT NULL
                            THEN COALESCE(lve_advisories.vendor_data, '{}'::jsonb) || v.vendor_data::jsonb
                            ELSE lve_advisories.vendor_data
                        END
                    FROM (VALUES %s) AS v(published, updated, vendor_data, lve_id, advisory_id)
                    WHERE lve_advisories.lve_id      = v.lve_id
                      AND lve_advisories.advisory_id = v.advisory_id
                """, upd_rows)

            if title_rows:
                seen, title_rows_deduped = set(), []
                for row in title_rows:
                    k = (row[0], row[2], row[3])
                    if k not in seen:
                        seen.add(k)
                        title_rows_deduped.append(row)
                execute_values(cur, """
                    INSERT INTO lve_titles (lve_id, value, source, advisory_ref) VALUES %s
                    ON CONFLICT (lve_id, source, advisory_ref) DO UPDATE SET value = EXCLUDED.value
                """, title_rows_deduped)

            if history_rows:
                execute_values(cur, """
                    INSERT INTO lve_history (lve_id, date, event, source, detail) VALUES %s
                    ON CONFLICT DO NOTHING
                """, history_rows)

    conn.commit()
    if not cve_filter:
        state.commit()
    print(f"  RedHat advisories: {adv_total:,} processed · {adv_errors} errors")
