"""Shared inheritance for the RHEL rebuilds (AlmaLinux / Rocky / Oracle).

These distros rebuild Red Hat's source RPMs, so Red Hat's affected rows (package ×
el-stream × status incl. the explicit not_affected) apply to them too. We project the
existing redhat affected rows onto each clone — DB→DB, no source re-parsing — tagged
`status_source = redhat-inherited` so it's transparent and auditable.

Notes:
  - The fixed EVR is Red Hat's (the clone adds a .alma/.rocky suffix, so the host's
    version compares >= it — same upstream fix point). Good enough for v1; a clone's
    own errata can overlay exact versions later.
  - Oracle's UEK is a different kernel, but it ships as `kernel-uek*` (a different
    package name) so it simply never matches an inherited `kernel` row — no special case.
  - A separate read connection streams the source rows so it doesn't clash with the
    orchestrator's write cursor.
"""
import os
import re

import psycopg2

from ingest.affected import row

_MAJ = re.compile(r"el(\d+)")
_SELECT = """SELECT cve_id, ecosystem, package, release, introduced, fixed,
                    last_affected, version_scheme, status, status_raw, justification
             FROM affected WHERE origin = 'redhat' AND release IS NOT NULL"""


def inherit(source: str, min_major: int | None = None):
    rconn = psycopg2.connect(os.environ["POSTGRES_DSN"])
    try:
        with rconn.cursor(name=f"rh_inherit_{source}") as cur:
            cur.itersize = 20_000
            cur.execute(_SELECT)
            for (cid, eco, pkg, rel, intro, fixed, last, scheme, status, sraw, just) in cur:
                if min_major:
                    m = _MAJ.search(rel or "")
                    if not m or int(m.group(1)) < min_major:
                        continue
                yield row(cve_id=cid, coord="purl", ecosystem=eco, package=pkg,
                          purl=f"pkg:rpm/{source}/{pkg}", release=rel, introduced=intro,
                          fixed=fixed, last_affected=last, version_scheme=scheme,
                          status=status, status_raw=sraw, justification=just,
                          source=source, status_source="redhat-inherited", origin=source)
    finally:
        rconn.close()
