"""GitHub repo advisories → affected (coord=purl).

The github_repo importer stored each advisory's affected packages in
``cve_vendor.data.packages`` as ``{purl, ranges}`` (same shape as ghsa). Non-ecosystem
software uses a synthetic ``pkg:github/{owner}/{repo}`` purl with the ``generic`` version
scheme, so ``fixed``/``last_affected`` are compared with the generic comparator.
"""
from ingest.affected import row
from ingest.affected import status as st
from ingest.match import parse_cpe

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


def _cpe_key(cpe: str | None):
    """Config CPEs are given as a short base (cpe:2.3:a:vendor:product); pad to the 13 CPE-2.3
    fields so parse_cpe accepts it, then take the normalised lookup key match_cpe() uses."""
    if not cpe:
        return None
    parts = cpe.split(":")
    return parse_cpe(":".join(parts + ["*"] * (13 - len(parts))))[0] if len(parts) < 13 \
        else parse_cpe(cpe)[0]


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
            # normalise the configured CPE to the exact key match_cpe() looks up (coord='cpe'),
            # so a scanner that reports the app by CPE (the usual non-ecosystem case) matches.
            cpe_key = _cpe_key(p.get("cpe"))
            for intro, fixed, last in _spans(p.get("ranges")):
                yield row(                                    # pkg:github coord (github-purl scanners)
                    cve_id=cid, coord="purl", ecosystem=eco, package=name, purl=base,
                    introduced=intro or "0", fixed=fixed, last_affected=last,
                    version_scheme=st.scheme(eco),
                    status=st.FIXED if fixed else st.AFFECTED,
                    source=SOURCE, status_source="own", origin=ORIGIN,
                )
                if cpe_key:                                   # cpe coord (real scanner CPEs)
                    yield row(
                        cve_id=cid, coord="cpe", cpe23=cpe_key,
                        introduced=intro or "0", fixed=fixed, last_affected=last,
                        version_scheme="generic",
                        status=st.FIXED if fixed else st.AFFECTED,
                        source=SOURCE, status_source="own", origin=ORIGIN,
                    )
