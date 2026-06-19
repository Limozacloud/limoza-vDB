import datetime
import json
import multiprocessing as mp
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from ingest.mapping import cvss_severity

import psycopg2
from psycopg2.extras import execute_values

_SCHEMA = Path(__file__).parent.parent / "schema.sql"
_conn   = None


def get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(os.environ["POSTGRES_DSN"])
        return _conn
    try:
        with _conn.cursor() as cur:
            cur.execute("SELECT 1")
    except psycopg2.OperationalError:
        _conn = psycopg2.connect(os.environ["POSTGRES_DSN"])
    return _conn


def sync_schema():
    parsed = urlparse(os.environ["POSTGRES_DSN"])
    env = os.environ.copy()
    env["PGHOST"]     = parsed.hostname or "localhost"
    env["PGPORT"]     = str(parsed.port or 5432)
    env["PGDATABASE"] = parsed.path.lstrip("/")
    env["PGUSER"]     = parsed.username or ""
    env["PGPASSWORD"] = parsed.password or ""
    subprocess.run(
        ["pgschema", "apply", "--file", str(_SCHEMA), "--auto-approve", "--no-color"],
        check=True,
        env=env,
    )


def _not_implemented(*args, **kwargs):
    raise NotImplementedError("This vendor has not been migrated to the v2 schema yet.")

upsert_cve_id             = _not_implemented
upsert_cve_nvd            = _not_implemented
upsert_source             = _not_implemented
upsert_advisory           = _not_implemented
upsert_cve_ghsa           = _not_implemented
bulk_upsert_cve_ids       = _not_implemented
bulk_upsert_product       = _not_implemented
bulk_upsert_cve_fix       = _not_implemented
bulk_upsert_cve_affected  = _not_implemented


_BULK_UPDATE_CVE_FIELDS = frozenset({
    "epss_score", "epss_percentile", "epss_date",
    "kev_date_added", "kev_due_date", "kev_known_ransomware", "kev_required_action",
    "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact",
    "status", "published", "updated",
})

def bulk_update_lve_cve(conn, rows: list[dict], fields: list[str], page_size: int = 5_000) -> int:
    """Bulk-update specific lve_cve columns for existing CVEs via a single UPDATE FROM VALUES.

    Only touches CVEs already present in lve_cve — no new rows are created.
    Each dict in rows must contain 'cve_id' plus every field in `fields`.
    Returns the approximate number of rows matched.
    """
    if not rows or not fields:
        return 0
    unknown = set(fields) - _BULK_UPDATE_CVE_FIELDS
    if unknown:
        raise ValueError(f"bulk_update_lve_cve: unknown fields {sorted(unknown)}")

    set_clause = ", ".join(f"{f} = v.{f}" for f in fields)
    col_list   = ", ".join(["cve_id"] + list(fields))
    sql = f"""
        UPDATE lve_cve SET {set_clause}
        FROM (VALUES %s) AS v({col_list})
        WHERE lve_cve.cve_id = v.cve_id
    """
    tuples = [tuple(row[k] for k in ["cve_id"] + list(fields)) for row in rows]
    with conn.cursor() as cur:
        execute_values(cur, sql, tuples, page_size=page_size)
    conn.commit()
    return len(rows)


INGEST_COMMIT_EVERY = 5_000


def ingest_records(
    conn,
    records,
    *,
    label: str,
    commit_every: int = INGEST_COMMIT_EVERY,
    cve_filter: str = None,
) -> tuple:
    """Import an in-memory iterator of record dicts.

    Returns (total_upserted, total_skipped, total_errors).
    """
    total = skipped = errors = processed = 0
    with conn.cursor() as cur:
        for rec in records:
            if cve_filter:
                if cve_filter not in (rec.get("aliases") or []):
                    skipped += 1
                    continue
            try:
                cur.execute("SAVEPOINT sp")
                upsert_lve_record(cur, rec)
                total += 1
                cur.execute("RELEASE SAVEPOINT sp")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                errors += 1
                if errors <= 5:
                    print(f"  Error: {e}", flush=True)
            processed += 1
            if not cve_filter and processed % commit_every == 0:
                conn.commit()
                print(f"  {label}: {processed:,}", flush=True)
    conn.commit()
    return total, skipped, errors


def _ingest_files_worker(args):
    """Multiprocessing worker for ingest_files() — must stay module-level to be picklable."""
    chunk_str, transform_fn, dsn, label, commit_every, worker_id = args
    import psycopg2 as _pg
    from ingest.db import upsert_lve_record as _upsert

    chunk = [Path(p) for p in chunk_str]
    conn  = _pg.connect(dsn)
    total = skipped = errors = 0
    n = len(chunk)

    with conn.cursor() as cur:
        for i, f in enumerate(chunk):
            try:
                cur.execute("SAVEPOINT sp")
                records = transform_fn(f)
                if not records:
                    skipped += 1
                    cur.execute("RELEASE SAVEPOINT sp")
                    continue
                if isinstance(records, dict):
                    records = [records]
                for rec in records:
                    _upsert(cur, rec)
                    total += 1
                cur.execute("RELEASE SAVEPOINT sp")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                errors += 1
                if errors <= 3:
                    print(f"  [w{worker_id}] Error {f.name}: {e}", flush=True)
            if (i + 1) % commit_every == 0:
                conn.commit()
                print(f"  [w{worker_id}] {i+1:,}/{n:,}", flush=True)

    conn.commit()
    conn.close()
    return total, skipped, errors


def ingest_files(
    conn,
    files: list,
    transform_fn,
    *,
    label: str,
    commit_every: int = INGEST_COMMIT_EVERY,
    state=None,
    cve_filter: str = None,
    n_workers: int = 1,
) -> tuple:
    """Standard file-based import loop with SAVEPOINT, batching, and optional parallelism.

    transform_fn(path: Path) → dict | list[dict] | None
        Return None or [] to skip the file.

    With n_workers > 1: transform_fn must be picklable (module-level function or
    functools.partial of one). State tracking is disabled in parallel mode —
    use for full imports where all files are already pre-selected.

    Returns (total_records_upserted, files_skipped, files_errored).
    """
    if not files:
        return 0, 0, 0

    if n_workers > 1 and not cve_filter:
        n          = min(n_workers, mp.cpu_count(), len(files))
        chunk_size = (len(files) + n - 1) // n
        chunks     = [files[i:i + chunk_size] for i in range(0, len(files), chunk_size)]
        dsn        = os.environ["POSTGRES_DSN"]
        worker_args = [
            ([str(f) for f in chunk], transform_fn, dsn, label, commit_every, i)
            for i, chunk in enumerate(chunks)
        ]
        print(f"  {label}: {n} workers · ~{chunk_size:,} files each")
        total = skipped = errors = 0
        with mp.Pool(n) as pool:
            for w_total, w_skipped, w_errors in pool.imap_unordered(_ingest_files_worker, worker_args):
                total   += w_total
                skipped += w_skipped
                errors  += w_errors
                print(f"  {label}: worker done · {total:,}/{len(files):,} records", flush=True)
        return total, skipped, errors

    # Single-process
    total = skipped = errors = 0
    n = len(files)
    with conn.cursor() as cur:
        for i, f in enumerate(files):
            f = Path(f)
            try:
                cur.execute("SAVEPOINT sp")
                records = transform_fn(f)
                if not records:
                    skipped += 1
                    cur.execute("RELEASE SAVEPOINT sp")
                    if state:
                        state.mark(f)
                    continue
                if isinstance(records, dict):
                    records = [records]
                inserted = 0
                for rec in records:
                    if cve_filter and cve_filter not in (rec.get("aliases") or []):
                        continue
                    upsert_lve_record(cur, rec)
                    inserted += 1
                total += inserted
                cur.execute("RELEASE SAVEPOINT sp")
                if state:
                    state.mark(f)
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT sp")
                errors += 1
                if errors <= 5:
                    print(f"  Error {f.name}: {e}", flush=True)
            if not cve_filter and n > commit_every and (i + 1) % commit_every == 0:
                conn.commit()
                print(f"  {label}: {i+1:,}/{n:,}", flush=True)
    conn.commit()
    if state and not cve_filter:
        state.commit()
    return total, skipped, errors


def _advisory_ref(a):
    if a is None:
        return None
    if isinstance(a, str):
        return a
    return a.get("@id")


_lve_id_cache: dict = {}


def clear_lve_cache() -> None:
    """Clear the in-process LVE ID cache (call between import runs if needed)."""
    _lve_id_cache.clear()


def _get_or_create_lve(cur, aliases: list) -> tuple:
    """Find existing LVE by alias overlap, or create a new one. Returns (lve_id, is_new).
    Lookup uses only CVE-format aliases to avoid merging unrelated LVEs that share an ADV.
    Results are cached in-process to avoid repeated DB round-trips for the same CVE."""
    for alias in aliases:
        if alias in _lve_id_cache:
            return _lve_id_cache[alias], False

    lookup = [a for a in aliases if a.startswith("CVE-")] or aliases
    if lookup:
        cur.execute(
            "SELECT lve_id FROM lve WHERE aliases && %s::text[]",
            (lookup,)
        )
        row = cur.fetchone()
        if row:
            lve_id = row[0]
            for alias in aliases:
                _lve_id_cache[alias] = lve_id
            return lve_id, False

    cur.execute("INSERT INTO lve (lve_id, aliases) VALUES (NULL, %s) RETURNING lve_id", (aliases,))
    lve_id = cur.fetchone()[0]
    for alias in aliases:
        _lve_id_cache[alias] = lve_id
    return lve_id, True


def upsert_lve_record(cur, r: dict) -> None:
    aliases = sorted(set(a.upper() for a in (r.get("aliases") or []) if a))

    lve_id, is_new = _get_or_create_lve(cur, aliases)

    # ── Capture existing state for diff-tracking (before any upserts) ────────
    existing_advisories:    set  = set()
    existing_packages:      dict = {}
    existing_cvss:          dict = {}
    existing_descriptions:  dict = {}

    if not is_new:
        cur.execute("SELECT advisory_id FROM lve_advisories WHERE lve_id = %s", (lve_id,))
        existing_advisories = {row[0] for row in cur.fetchall()}

        cur.execute(
            "SELECT purl, source, affected_state, remediation_state, severity FROM lve_packages WHERE lve_id = %s",
            (lve_id,)
        )
        existing_packages = {
            (row[0], row[1]): {"affected_state": row[2], "remediation_state": row[3], "severity": row[4]}
            for row in cur.fetchall()
        }

        cur.execute("SELECT vector, source, score FROM lve_cvss WHERE lve_id = %s", (lve_id,))
        existing_cvss = {(row[0], row[1]): row[2] for row in cur.fetchall()}

        cur.execute("SELECT source, value FROM lve_descriptions WHERE lve_id = %s", (lve_id,))
        existing_descriptions = {row[0]: row[1] for row in cur.fetchall()}
    # ─────────────────────────────────────────────────────────────────────────

    if is_new:
        cur.execute(
            "UPDATE lve SET has_exploit = %s WHERE lve_id = %s",
            (r.get("has_exploit", False), lve_id)
        )
    else:
        cur.execute("""
            UPDATE lve SET
                aliases     = COALESCE((SELECT array_agg(DISTINCT x) FROM unnest(aliases || %s::text[]) x WHERE x IS NOT NULL), '{}'),
                has_exploit = has_exploit OR %s,
                ingested_at = now()
            WHERE lve_id = %s
        """, (aliases, r.get("has_exploit", False), lve_id))

    cve = r.get("cve")
    if cve:
        epss = cve.get("epss") or {}
        kev  = cve.get("kev")  or {}
        ssvc = cve.get("ssvc") or {}
        cur.execute("""
            INSERT INTO lve_cve (lve_id, cve_id, status, published, updated,
                epss_score, epss_percentile, epss_date,
                kev_date_added, kev_due_date, kev_known_ransomware, kev_required_action,
                ssvc_exploitation, ssvc_automatable, ssvc_technical_impact)
            VALUES (%s,%s,%s,%s,%s, %s,%s,%s, %s,%s,%s,%s, %s,%s,%s)
            ON CONFLICT (lve_id) DO UPDATE SET
                status    = COALESCE(EXCLUDED.status,    lve_cve.status),
                published = COALESCE(EXCLUDED.published, lve_cve.published),
                updated   = COALESCE(EXCLUDED.updated,   lve_cve.updated),
                epss_score           = COALESCE(EXCLUDED.epss_score,           lve_cve.epss_score),
                epss_percentile      = COALESCE(EXCLUDED.epss_percentile,      lve_cve.epss_percentile),
                epss_date            = COALESCE(EXCLUDED.epss_date,            lve_cve.epss_date),
                kev_date_added       = COALESCE(EXCLUDED.kev_date_added,       lve_cve.kev_date_added),
                kev_due_date         = COALESCE(EXCLUDED.kev_due_date,         lve_cve.kev_due_date),
                kev_known_ransomware = COALESCE(EXCLUDED.kev_known_ransomware, lve_cve.kev_known_ransomware),
                kev_required_action  = COALESCE(EXCLUDED.kev_required_action,  lve_cve.kev_required_action),
                ssvc_exploitation    = COALESCE(EXCLUDED.ssvc_exploitation,    lve_cve.ssvc_exploitation),
                ssvc_automatable     = COALESCE(EXCLUDED.ssvc_automatable,     lve_cve.ssvc_automatable),
                ssvc_technical_impact= COALESCE(EXCLUDED.ssvc_technical_impact,lve_cve.ssvc_technical_impact)
        """, (
            lve_id, cve.get("cve_id"), cve.get("status"),
            cve.get("published"), cve.get("updated"),
            epss.get("score"), epss.get("percentile"), epss.get("date"),
            kev.get("date_added"), kev.get("due_date"), kev.get("known_ransomware"), kev.get("required_action"),
            ssvc.get("exploitation"), ssvc.get("automatable"), ssvc.get("technical_impact"),
        ))

    def _dedup(items, *key_fields):
        seen, out = set(), []
        for item in (items or []):
            k = tuple(item.get(f) for f in key_fields)
            if k not in seen:
                seen.add(k)
                out.append(item)
        return out

    titles = _dedup(r.get("titles"), "source", "advisory")
    if titles:
        execute_values(cur, """
            INSERT INTO lve_titles (lve_id, value, source, advisory_ref) VALUES %s
            ON CONFLICT (lve_id, source, advisory_ref) DO UPDATE SET
                value = EXCLUDED.value
        """, [(lve_id, t["value"], t["source"], _advisory_ref(t.get("advisory"))) for t in titles])

    descriptions = _dedup(r.get("descriptions"), "source", "advisory")
    if descriptions:
        execute_values(cur, """
            INSERT INTO lve_descriptions (lve_id, value, source, advisory_ref) VALUES %s
            ON CONFLICT (lve_id, source, advisory_ref) DO UPDATE SET
                value = EXCLUDED.value
        """, [(lve_id, d["value"], d["source"], _advisory_ref(d.get("advisory"))) for d in descriptions])

    cvss = _dedup(r.get("cvss"), "vector", "source")
    if cvss:
        execute_values(cur, """
            INSERT INTO lve_cvss (lve_id, version, score, vector, severity, source, advisory_ref, product_id) VALUES %s
            ON CONFLICT (lve_id, vector, source) DO UPDATE SET
                version = EXCLUDED.version, score = EXCLUDED.score,
                severity = EXCLUDED.severity, advisory_ref = EXCLUDED.advisory_ref,
                product_id = EXCLUDED.product_id
        """, [(lve_id, c["version"], c["score"], c["vector"],
               c.get("severity") or cvss_severity(c.get("score")),
               c["source"], _advisory_ref(c.get("advisory")),
               c.get("product_id")) for c in cvss])

    cwes = _dedup(r.get("cwes"), "id", "source")
    if cwes:
        execute_values(cur, """
            INSERT INTO lve_cwes (lve_id, cwe_id, source, advisory_ref) VALUES %s
            ON CONFLICT (lve_id, cwe_id, source) DO UPDATE SET
                advisory_ref = EXCLUDED.advisory_ref
        """, [(lve_id, c["id"], c["source"], _advisory_ref(c.get("advisory"))) for c in cwes])

    refs = _dedup(r.get("references"), "url")
    if refs:
        execute_values(cur, """
            INSERT INTO lve_references (lve_id, url, type, source, advisory_ref) VALUES %s
            ON CONFLICT (lve_id, url, source) DO UPDATE SET
                type = EXCLUDED.type, advisory_ref = EXCLUDED.advisory_ref
        """, [(lve_id, ref["url"], ref["type"], ref.get("source"),
               _advisory_ref(ref.get("advisory"))) for ref in refs])

    advisories = _dedup(r.get("advisories"), "@id")
    if advisories:
        execute_values(cur, """
            INSERT INTO lve_advisories (lve_id, advisory_id, source, url, published, updated, vendor_data) VALUES %s
            ON CONFLICT (lve_id, advisory_id) DO UPDATE SET
                url = EXCLUDED.url, published = EXCLUDED.published,
                updated = EXCLUDED.updated, vendor_data = EXCLUDED.vendor_data
        """, [(lve_id, a["@id"], a["source"], a.get("url"), a.get("published"), a.get("updated"),
               json.dumps(a["vendor_data"]) if a.get("vendor_data") else None) for a in advisories])

    upstream = _dedup(r.get("upstream"), "@id")
    if upstream:
        execute_values(cur, """
            INSERT INTO lve_upstream (lve_id, upstream_id, purl, fix_version, fix_commit, ranges, versions, source, advisory_ref) VALUES %s
            ON CONFLICT (lve_id, upstream_id) DO UPDATE SET
                purl = EXCLUDED.purl, fix_version = EXCLUDED.fix_version,
                fix_commit = EXCLUDED.fix_commit, ranges = EXCLUDED.ranges,
                versions = EXCLUDED.versions, advisory_ref = EXCLUDED.advisory_ref
        """, [(lve_id, u["@id"], u["purl"], u.get("fix_version"), u.get("fix_commit"),
               json.dumps(u["ranges"]) if u.get("ranges") else None,
               u.get("versions") or None,
               u["source"], _advisory_ref(u.get("advisory"))) for u in upstream])

    packages = _dedup(r.get("packages"), "purl", "source")
    if packages:
        execute_values(cur, """
            INSERT INTO lve_packages
                (lve_id, name, purl, affected_state, remediation_state, status_raw,
                 vex_justification, ranges, source, advisory_ref, upstream_ref, severity, vendor_data)
            VALUES %s
            ON CONFLICT (lve_id, purl, source) DO UPDATE SET
                name              = EXCLUDED.name,
                affected_state    = EXCLUDED.affected_state,
                remediation_state = EXCLUDED.remediation_state,
                status_raw        = EXCLUDED.status_raw,
                vex_justification = EXCLUDED.vex_justification,
                ranges            = EXCLUDED.ranges,
                advisory_ref      = EXCLUDED.advisory_ref,
                upstream_ref      = EXCLUDED.upstream_ref,
                severity          = EXCLUDED.severity,
                vendor_data       = EXCLUDED.vendor_data
        """, [(lve_id, p.get("name"), p["purl"],
               p.get("affected_state", "unknown"), p.get("remediation_state", "unknown"),
               p.get("status_raw"),
               p.get("vex_justification"),
               json.dumps(p["ranges"]) if p.get("ranges") else None,
               p["source"],
               _advisory_ref(p.get("advisory")),
               _advisory_ref(p.get("upstream")),
               p.get("severity"),
               json.dumps(p["vendor_data"]) if p.get("vendor_data") else None)
              for p in packages])

    exploits = _dedup(r.get("exploits"), "url")
    if exploits:
        execute_values(cur, """
            INSERT INTO lve_exploits (lve_id, source, source_id, name, url, metadata) VALUES %s
            ON CONFLICT (lve_id, url) DO NOTHING
        """, [(lve_id, e["source"], e.get("source_id"), e.get("name"), e["url"],
               json.dumps(e["metadata"]) if e.get("metadata") else None)
              for e in exploits])

    mitigations = _dedup(r.get("mitigations"), "source", "advisory")
    if mitigations:
        execute_values(cur, """
            INSERT INTO lve_mitigations (lve_id, value, source, advisory_ref, purls) VALUES %s
            ON CONFLICT (lve_id, source, advisory_ref) DO UPDATE SET
                value = EXCLUDED.value, purls = EXCLUDED.purls
        """, [(lve_id, m["value"], m["source"], _advisory_ref(m.get("advisory")),
               m.get("purls")) for m in mitigations])

    impacts = _dedup(r.get("impacts"), "source", "advisory")
    if impacts:
        execute_values(cur, """
            INSERT INTO lve_impacts (lve_id, value, source, advisory_ref) VALUES %s
            ON CONFLICT (lve_id, source, advisory_ref) DO UPDATE SET
                value = EXCLUDED.value
        """, [(lve_id, i["value"], i["source"], _advisory_ref(i.get("advisory")))
              for i in impacts])

    notices = r.get("notices") or []
    if notices:
        execute_values(cur, """
            INSERT INTO notices (type, source, message, metadata) VALUES %s
            ON CONFLICT (type, source, message) DO NOTHING
        """, [(n["type"], n["source"], n["message"],
               json.dumps(n["metadata"]) if n.get("metadata") else None) for n in notices])

    # ── History ───────────────────────────────────────────────────────────────
    # Part 1 — vendor-native timestamps from transform (advisory issued/updated dates)
    # Deduped by (event, source, detail) so re-imports don't create duplicates.
    vendor_history = list(r.get("history") or [])
    if vendor_history:
        cur.execute(
            "SELECT event, source, detail FROM lve_history WHERE lve_id = %s",
            (lve_id,)
        )
        existing_hist_keys = {(row[0], row[1], row[2]) for row in cur.fetchall()}
        new_vendor_hist = [
            h for h in vendor_history
            if (h["event"], h["source"], h.get("detail")) not in existing_hist_keys
        ]
        if new_vendor_hist:
            execute_values(cur, """
                INSERT INTO lve_history
                    (lve_id, date, event, source, detail)
                VALUES %s
                ON CONFLICT DO NOTHING
            """, [(lve_id, h["date"], h["event"], h["source"], h.get("detail"))
                  for h in new_vendor_hist])

    # Part 2 — diff-tracking: detect what changed in this import run
    if not is_new:
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        diff_history = []

        for a in (advisories or []):
            if a["@id"] not in existing_advisories:
                diff_history.append({
                    "date": now_str, "event": "advisory_added",
                    "source": a.get("source", ""), "detail": a["@id"],
                })

        for p in (packages or []):
            key = (p["purl"], p["source"])
            old = existing_packages.get(key)
            if old:
                new_rs = p.get("remediation_state", "unknown")
                if old["remediation_state"] != new_rs:
                    diff_history.append({
                        "date": now_str, "event": "remediation_state_changed",
                        "source": p["source"], "detail": p["purl"],
                    })
                new_as = p.get("affected_state", "unknown")
                if old["affected_state"] != new_as:
                    diff_history.append({
                        "date": now_str, "event": "affected_state_changed",
                        "source": p["source"], "detail": p["purl"],
                    })
                if old["severity"] != p.get("severity"):
                    diff_history.append({
                        "date": now_str, "event": "severity_changed",
                        "source": p["source"], "detail": p["purl"],
                    })

        for c in (cvss or []):
            key = (c["vector"], c["source"])
            old_score = existing_cvss.get(key)
            if old_score is not None and float(old_score) != float(c["score"]):
                diff_history.append({
                    "date": now_str, "event": "cvss_updated",
                    "source": c["source"], "detail": c.get("vector", ""),
                })

        for d in (descriptions or []):
            old_val = existing_descriptions.get(d["source"])
            if old_val is not None and old_val != d["value"]:
                diff_history.append({
                    "date": now_str, "event": "description_updated",
                    "source": d["source"], "detail": None,
                })

        if diff_history:
            execute_values(cur, """
                INSERT INTO lve_history
                    (lve_id, date, event, source, detail)
                VALUES %s
                ON CONFLICT DO NOTHING
            """, [(lve_id, h["date"], h["event"], h["source"], h.get("detail"))
                  for h in diff_history])
    # ─────────────────────────────────────────────────────────────────────────
