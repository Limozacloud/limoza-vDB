"""NVD CVE 2.0 → affected (coord=cpe) — the authoritative CPE lane.

NVD enriches each CVE with CPE applicability (`configurations[].nodes[].cpeMatch[]`),
which the CNA records (cvelistv5) usually lack. We turn each vulnerable match into a
cpe-coordinate range:

    criteria                → cpe (vendor:product; the version field → *)
    versionStartIncluding   → introduced (inclusive lower bound)
    versionStartExcluding   → introduced (treated as the lower bound)
    versionEndExcluding     → fixed         (exclusive upper)
    versionEndIncluding     → last_affected (inclusive upper)
    bare version in criteria → exact (last_affected = that version)

Only `vulnerable: true` matches are kept; Microsoft is excluded (MSRC is authoritative).
NVD is the PRIMARY cpe source — the cvelistv5 synthesis fallback only fills CVEs NVD has
no configuration for.
"""
import glob
import json
from pathlib import Path

from ingest.affected import cpe_norm, row
from ingest.affected import status as st

ORIGIN = SOURCE = "nvd"
_VAGUE = {"*", "-", ""}


def _norm_cpe(cpe: str):
    """NVD-validated canonical cpe, or None. Microsoft excluded (MSRC authoritative)."""
    p = (cpe or "").split(":")
    if len(p) < 6 or p[0] != "cpe" or p[3].lower() == "microsoft":
        return None
    return cpe_norm.canonical(cpe)[0]


def _matches(cfgs):
    """Walk configurations → nodes (incl. nested children) → vulnerable cpeMatch entries."""
    for cfg in cfgs or []:
        stack = list(cfg.get("nodes") or [])
        while stack:
            n = stack.pop()
            stack.extend(n.get("children") or [])
            for m in n.get("cpeMatch") or []:
                if m.get("vulnerable"):
                    yield m


def _file_rows(d: dict):
    cve = d.get("cve", d)                     # accept {"cve": {...}} or the bare cve object
    cid = cve.get("id")
    if not cid:
        return
    seen = set()
    for m in _matches(cve.get("configurations")):
        cpe = _norm_cpe(m.get("criteria"))
        if not cpe:
            continue
        start = m.get("versionStartIncluding") or m.get("versionStartExcluding")
        end_excl = m.get("versionEndExcluding")
        end_incl = m.get("versionEndIncluding")
        crit = (m.get("criteria") or "").split(":")
        bare = crit[5] if len(crit) > 5 and crit[5] not in _VAGUE else None
        if end_excl:
            intro, fixed, last = start or "0", end_excl, None
        elif end_incl:
            intro, fixed, last = start or "0", None, end_incl
        elif start:
            intro, fixed, last = start, None, None        # open-ended from start (no fix yet)
        elif bare:
            intro, fixed, last = bare, None, bare          # exact version
        else:
            continue                                       # cpe with no version info → too broad, skip
        key = (cpe, intro, fixed, last)
        if key in seen:
            continue
        seen.add(key)
        yield row(cve_id=cid, coord="cpe", cpe23=cpe, package=cpe.split(":")[4],
                  introduced=intro, fixed=fixed, last_affected=last,
                  version_scheme="generic", status=st.AFFECTED,
                  source=SOURCE, status_source="own", origin=ORIGIN)


def extract(conn, dirs):
    cpe_norm.load(conn)
    base = Path(dirs["nvd"]) / "repo"
    for f in glob.iglob(str(base / "**" / "CVE-*.json"), recursive=True):
        try:
            d = json.loads(Path(f).read_bytes())
        except Exception:
            continue
        yield from _file_rows(d)
