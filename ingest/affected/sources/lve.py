"""LVE → affected. Materialise the user-defined `lve` table into affected rows
(origin='lve', cve_id = the LVE id) so the matcher checks custom entries like any CVE.

The `lve` table is the source of truth — never touched by sync/ingest — so re-seeding
the affected rows from it on every pass makes them survive any affected truncate/rebuild
(exactly like a distro's rows are re-derived from /data). A separate read connection
streams the rows so it doesn't clash with the orchestrator's write cursor.
"""
import os

import psycopg2

from ingest.affected import row

ORIGIN = SOURCE = "lve"

_SELECT = """SELECT id, coord, ecosystem, package, purl, cpe23, release,
                    introduced, fixed, last_affected, version_scheme, status
             FROM lve"""


def extract(conn, dirs):
    rconn = psycopg2.connect(os.environ["POSTGRES_DSN"])
    try:
        with rconn.cursor() as cur:
            cur.execute(_SELECT)
            for (lid, coord, eco, pkg, purl, cpe23, rel,
                 intro, fixed, last, scheme, status) in cur:
                yield row(cve_id=lid, coord=coord, ecosystem=eco, package=pkg, purl=purl,
                          cpe23=cpe23, release=rel, introduced=intro, fixed=fixed,
                          last_affected=last, version_scheme=scheme or "generic",
                          status=status, source=SOURCE, status_source="lve", origin=ORIGIN)
    finally:
        rconn.close()
