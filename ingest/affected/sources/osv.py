"""OSV native ecosystems → affected (coord=purl).

Reads the affected packages the osv importer now stores in cve_vendor.data.packages
for pypa/go/rustsec/eef/drupal — same projection as GHSA. origin='osv' (one
delete-scope), source = the native DB (pypa/go/…).
"""
from ingest.affected import row
from ingest.affected import status as st
from ingest.affected.sources.ghsa import _eco_name, _spans

ORIGIN = "osv"
SOURCES = ("pypa", "go", "rustsec", "eef", "drupal")


def extract(conn, dirs):
    with conn.cursor() as cur:
        cur.execute("SELECT cve_id, source, data->'packages' FROM cve_vendor WHERE source = ANY(%s)",
                    (list(SOURCES),))
        rows = cur.fetchall()
    for cid, src, pkgs in rows:
        for p in pkgs or []:
            purl = p.get("purl")
            if not purl:
                continue
            base = purl.split("@", 1)[0]
            eco, name = _eco_name(base)
            for intro, fixed, last in _spans(p.get("ranges")):
                yield row(cve_id=cid, coord="purl", ecosystem=eco, package=name, purl=base,
                          introduced=intro or "0", fixed=fixed, last_affected=last,
                          version_scheme=st.scheme(eco),
                          status=st.FIXED if fixed else st.AFFECTED,
                          source=src, status_source="own", origin=ORIGIN)
