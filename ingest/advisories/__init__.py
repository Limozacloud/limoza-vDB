"""Shared helpers for advisory sources (redhat, later suse/ubuntu/ghsa).

Every advisory source writes the same shape:
  - the issuer's per-CVE enrichment → cve_* tables with origin=<source>
  - the advisory object + CVE links  → advisory / advisory_cve
  - the per-CVE vendor assessment    → cve_vendor (data JSONB)
Affected/version status is phase 3 and not handled here.

Each source rebuilds only its own slice (delete_scope) before reinserting, so
the swap is dashboard-safe and other sources are untouched.
"""
from psycopg2.extras import execute_values

_CVE_ENRICH = ("cve_cvss", "cve_cwe", "cve_ref", "cve_desc",
               "cve_solution", "cve_workaround", "cve_impact")


def new_bundle() -> dict:
    return {k: [] for k in (
        "spine", "cvss", "cwe", "ref", "desc", "solution", "workaround", "impact",
        "advisory", "advisory_cve", "cve_vendor",
    )}


def delete_scope(conn, origin: str, source: str) -> None:
    """Remove this source's slice so it can be cleanly reinserted."""
    with conn.cursor() as cur:
        for t in _CVE_ENRICH:
            cur.execute(f"DELETE FROM {t} WHERE origin = %s", (origin,))
        cur.execute("DELETE FROM advisory     WHERE source = %s", (source,))
        cur.execute("DELETE FROM advisory_cve WHERE source = %s", (source,))
        cur.execute("DELETE FROM cve_vendor   WHERE source = %s", (source,))
    conn.commit()


def flush(cur, b: dict) -> None:
    """Insert one bundle of row-lists. Idempotent via ON CONFLICT."""
    if b["spine"]:
        execute_values(cur, "INSERT INTO cve (cve_id) VALUES %s ON CONFLICT DO NOTHING", b["spine"])
    if b["cvss"]:
        execute_values(cur, "INSERT INTO cve_cvss (cve_id,origin,source,version,base_score,severity,vector) VALUES %s ON CONFLICT (cve_id,origin,source,vector) DO NOTHING", b["cvss"])
    if b["cwe"]:
        execute_values(cur, "INSERT INTO cve_cwe (cve_id,origin,source,cwe_id) VALUES %s ON CONFLICT (cve_id,origin,source,cwe_id) DO NOTHING", b["cwe"])
    if b["ref"]:
        execute_values(cur, "INSERT INTO cve_ref (cve_id,origin,source,url,type) VALUES %s ON CONFLICT (cve_id,origin,source,url) DO NOTHING", b["ref"])
    if b["desc"]:
        execute_values(cur, "INSERT INTO cve_desc (cve_id,origin,source,lang,value) VALUES %s ON CONFLICT (cve_id,origin,source,lang) DO NOTHING", b["desc"])
    if b["solution"]:
        execute_values(cur, "INSERT INTO cve_solution (cve_id,origin,source,lang,value) VALUES %s ON CONFLICT (cve_id,origin,source,lang) DO NOTHING", b["solution"])
    if b["workaround"]:
        execute_values(cur, "INSERT INTO cve_workaround (cve_id,origin,source,lang,value) VALUES %s ON CONFLICT (cve_id,origin,source,lang) DO NOTHING", b["workaround"])
    if b["impact"]:
        execute_values(cur, "INSERT INTO cve_impact (cve_id,origin,source,capec_id,description) VALUES %s", b["impact"])
    if b["advisory"]:
        execute_values(cur, "INSERT INTO advisory (source,advisory_id,url,title,severity,published,modified) VALUES %s ON CONFLICT (source,advisory_id) DO NOTHING", b["advisory"], template="(%s,%s,%s,%s,%s,%s,%s)")
    if b["advisory_cve"]:
        execute_values(cur, "INSERT INTO advisory_cve (source,advisory_id,cve_id) VALUES %s ON CONFLICT DO NOTHING", b["advisory_cve"])
    if b["cve_vendor"]:
        execute_values(cur, "INSERT INTO cve_vendor (cve_id,source,data) VALUES %s ON CONFLICT (cve_id,source) DO NOTHING", b["cve_vendor"])
