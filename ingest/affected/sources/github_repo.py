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


def _branch_floors(spans, per_branch=False):
    """Give parallel fix branches their own lower bound.

    A multi-branch repo advisory lists one open-ended span per maintained branch (php-src:
    '<8.2.35', '<8.3.36', '<8.4.27', '<8.5.12'). Left at introduced='0' they form ONE range,
    and the matcher clears a host that reaches ANY of its fixes — a vulnerable 8.3.30 would
    pass on 8.2.35. Each branch therefore starts at its fix's major.minor; by default the
    lowest branch keeps '0' so anything older stays affected (the advisory's literal reading).
    ``per_branch`` (repo config "branch_floors") floors every span, the lowest and a lone one
    too: for projects that version each fix per release branch, '<8.4.24' means 8.4.x before
    8.4.24 (the CNA record / NVD say 8.4.0–8.4.23), never 8.3 or 7.4. Applied only when every
    open-ended fix is a dotted x.y.z on a distinct major.minor; otherwise unchanged."""
    open_ = [s for s in spans if not s[0] and s[1]]
    if len(open_) < (1 if per_branch else 2):
        return spans
    floors = {}
    for s in open_:
        p = s[1].split(".")
        if len(p) < 3 or not (p[0].isdigit() and p[1].isdigit()) or p[2] == "0":
            return spans                       # x.y.0 fixes a whole older series: no branch floor
        floors[s] = (int(p[0]), int(p[1]))
    if len(set(floors.values())) != len(floors):
        return spans
    lowest = None if per_branch else min(floors.values())
    return [(f"{floors[s][0]}.{floors[s][1]}" if s in floors and floors[s] != lowest else s[0],
             s[1], s[2]) for s in spans]


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
        # an advisory lists each fix branch as its own package entry → collect per purl first
        by_purl = {}
        for p in pkgs or []:
            purl = p.get("purl")
            if not purl:
                continue
            base = purl.split("@", 1)[0]
            entry = by_purl.setdefault(base, {"cpe": p.get("cpe"), "spans": [],
                                              "per_branch": bool(p.get("branch_floors"))})
            for span in _spans(p.get("ranges")):
                if span not in entry["spans"]:
                    entry["spans"].append(span)
        for base, entry in by_purl.items():
            eco, name = _eco_name(base)
            # normalise the configured CPE to the exact key match_cpe() looks up (coord='cpe'),
            # so a scanner that reports the app by CPE (the usual non-ecosystem case) matches.
            cpe_key = _cpe_key(entry["cpe"])
            spans = entry["spans"]
            if entry["per_branch"]:
                # a per-branch project's advisory without any version range can't be scoped to
                # a branch — "every release ever" would flag patched hosts; NVD/CNA still cover it
                spans = [s for s in spans if any(s)]
            for intro, fixed, last in _branch_floors(spans, entry["per_branch"]):
                yield row(                                    # pkg:github coord (github-purl scanners)
                    cve_id=cid, coord="purl", ecosystem=eco, package=name, purl=base,
                    introduced=intro or "0", fixed=fixed, last_affected=last,
                    version_scheme=st.scheme(eco),
                    status=st.FIXED if fixed else st.AFFECTED,
                    source=SOURCE, status_source="own", origin=ORIGIN,
                )
                if cpe_key:                                   # cpe coord (real scanner CPEs)
                    yield row(
                        cve_id=cid, coord="cpe", cpe23=cpe_key, package=cpe_key.split(":")[4],
                        introduced=intro or "0", fixed=fixed, last_affected=last,
                        version_scheme="generic",
                        status=st.FIXED if fixed else st.AFFECTED,
                        source=SOURCE, status_source="own", origin=ORIGIN,
                    )
