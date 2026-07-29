"""GitHub repo advisories → affected (coord=purl).

The github_repo importer stored each advisory's affected packages in
``cve_vendor.data.packages`` as ``{purl, ranges}`` (same shape as ghsa). Non-ecosystem
software uses a synthetic ``pkg:github/{owner}/{repo}`` purl with the ``generic`` version
scheme, so ``fixed``/``last_affected`` are compared with the generic comparator.
"""
from ingest.affected import row
from ingest.affected import status as st

ORIGIN = SOURCE = "github_repo"


def _spans(ranges: str | None):
    """'>=1.0 <2.0; <=3.4' → [(introduced, fixed, last_affected), …]."""
    if not ranges:
        return [(None, None, None)]
    out = []
    for span in ranges.split(";"):
        intro = fixed = last = None
        for tok in span.split():
            if tok.startswith(">="):
                intro = tok[2:]
            elif tok.startswith("<="):
                last = tok[2:]
            elif tok.startswith("<"):
                fixed = tok[1:]
        out.append((intro, fixed, last))
    return out or [(None, None, None)]


def _eco_name(purl_base: str):
    # pkg:github/owner/repo → ('github', 'owner/repo') ; pkg:pypi/django → ('pypi', 'django')
    body = purl_base[4:] if purl_base.startswith("pkg:") else purl_base
    eco, _, name = body.partition("/")
    return eco or None, (name or None)


def extract(conn, dirs):
    with conn.cursor() as cur:
        cur.execute("SELECT cve_id, data->'packages' FROM cve_vendor WHERE source = %s", (SOURCE,))
        rows = cur.fetchall()
    for cid, pkgs in rows:
        for p in pkgs or []:
            purl = p.get("purl")
            if not purl:
                continue
            base = purl.split("@", 1)[0]
            eco, name = _eco_name(base)
            for intro, fixed, last in _spans(p.get("ranges")):
                yield row(
                    cve_id=cid, coord="purl", ecosystem=eco, package=name, purl=base,
                    introduced=intro or "0", fixed=fixed, last_affected=last,
                    version_scheme=st.scheme(eco),
                    status=st.FIXED if fixed else st.AFFECTED,
                    source=SOURCE, status_source="own", origin=ORIGIN,
                )
