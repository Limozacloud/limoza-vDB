"""Ingest SUSE CVE data from local CSAF VEX and Advisory caches."""
import functools
import json
from pathlib import Path

from ingest.db import ingest_files
from ingest.incremental import ImportState
from ingest.suse.transform import transform, transform_advisory
from psycopg2.extras import execute_values

N_WORKERS = 8


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


def _transform_vex_file(f: Path, *, adv_map):
    """Module-level so functools.partial of this is picklable for multiprocessing."""
    data = json.loads(f.read_bytes())
    return transform(data, adv_map)


def ingest(conn, dirs: dict, cve_filter: str = None, full: bool = False) -> None:
    base = Path(dirs["suse_vex"])
    if not base.exists():
        print(f"  SUSE: {base} not found — run `sync suse` first")
        return

    adv_map = _load_adv_map(base)
    state   = ImportState(base / ".import_state.json", base)

    # ── VEX import ────────────────────────────────────────────────────────────
    if cve_filter:
        fname = cve_filter.lower() + ".json"
        found = next(base.rglob(fname), None)
        files = [found] if found else []
        print(f"  SUSE VEX: filter {cve_filter} → {len(files)} files")
    else:
        all_files = sorted(base.rglob("cve-*.json"))
        files     = state.changed(all_files, full=full)
        print(f"  SUSE VEX: {len(files):,} changed of {len(all_files):,} CVE files")

    fn = functools.partial(_transform_vex_file, adv_map=adv_map)
    total, skipped, errors = ingest_files(conn, files, fn,
        label="SUSE VEX", state=state, cve_filter=cve_filter,
        n_workers=N_WORKERS if not cve_filter else 1)
    print(f"  SUSE VEX: {total:,} upserted · {skipped} skipped · {errors} errors")

    # ── Advisory import ───────────────────────────────────────────────────────
    adv_base = base / "advisories"
    if not adv_base.exists():
        print(f"  SUSE advisories: {adv_base} not found — skipping")
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
        print(f"  SUSE advisories: {len(adv_files)} files")
    else:
        all_adv   = sorted(adv_base.glob("*.json"))
        adv_files = state.changed(all_adv, full=full)
        print(f"  SUSE advisories: {len(adv_files):,} changed of {len(all_adv):,} files")

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
                upd_rows.append((rec["published"], rec["updated"], lve_id, rec["adv_id"]))
                if rec["title"]:
                    title_rows.append((lve_id, rec["title"], "suse", rec["adv_id"]))
                for h in rec.get("history") or []:
                    history_rows.append((lve_id, h["date"], h["event"], h["source"], h.get("detail")))

            if upd_rows:
                execute_values(cur, """
                    UPDATE lve_advisories
                    SET published = COALESCE(v.published::timestamptz, lve_advisories.published),
                        updated   = COALESCE(v.updated::timestamptz,   lve_advisories.updated)
                    FROM (VALUES %s) AS v(published, updated, lve_id, advisory_id)
                    WHERE lve_advisories.lve_id       = v.lve_id
                      AND lve_advisories.advisory_id  = v.advisory_id
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
    print(f"  SUSE advisories: {adv_total:,} processed · {adv_errors} errors")
