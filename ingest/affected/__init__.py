"""L4 — affected-version layer.

A central post-pass (``vdb affected``) that runs once after sync+ingest and derives,
per (cve, package, release), the affected version range plus a canonical VEX status.
Two coordinate systems share one table:

  coord='purl'  managed / ecosystem software   (rpm/deb/apk, pypi/npm/…)
  coord='cpe'   unmanaged / binaries           (vendor:product from CVE/NVD)

``status`` is the canonical six-value enum (see :mod:`ingest.affected.status`) that
drives the matcher; ``status_raw`` keeps the source's original wording for audit.

Each per-source extractor lives in ``ingest/affected/sources/`` and yields rows via
:func:`row`; the orchestrator (:mod:`ingest.affected.run`) delete-scopes that source's
slice (by ``origin``) and reinserts.
"""
from psycopg2.extras import execute_values

# column order — shared by row() and flush()
COLS = (
    "cve_id", "coord", "ecosystem", "package", "purl", "cpe23", "release",
    "introduced", "fixed", "last_affected", "version_scheme",
    "status", "status_raw", "justification", "source", "status_source", "origin",
)


def row(**kw) -> tuple:
    """Build an affected-row tuple from keyword fields (missing → NULL)."""
    return tuple(kw.get(c) for c in COLS)


def delete_scope(conn, origin: str) -> None:
    """Drop one extractor's slice so it can be cleanly re-derived."""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM affected WHERE origin = %s", (origin,))
    conn.commit()


def flush(cur, rows: list) -> None:
    if rows:
        execute_values(cur, "INSERT INTO affected (" + ",".join(COLS) + ") VALUES %s", rows)
