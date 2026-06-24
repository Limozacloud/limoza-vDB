"""Microsoft MSRC CVRF → affected (coord=cpe) — the Windows / Microsoft-product lane.

Microsoft patches by BUILD number, not package version: a product (a Windows release
or an app like SQL Server) is identified by its CPE, and a CVE is fixed at a specific
build. We read each monthly CVRF document:

    ProductTree.FullProductName  →  ProductID → CPE (or, when MSRC gives none, the name)
    Vulnerability[].Remediations →  FixedBuild + the ProductID[] it applies to

and emit one affected row per (CVE, product): coord='cpe', cpe23 resolved+validated
against the NVD catalog (see :mod:`ingest.affected.cpe_norm`), fixed=<build>. Only
CVE-bearing entries are kept; every remediation SubType that carries a FixedBuild counts.
Products whose CPE can't be validated against NVD (and Microsoft's own Linux, CBL/Azure
Linux) are dropped — we only store CPEs a scanner can actually produce.
"""
import glob
import json
import re
from pathlib import Path

from ingest.affected import cpe_norm, row
from ingest.affected import status as st
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "microsoft"

# Office family uses the 16.0.MMMM.PPPP build scheme; MSRC sometimes drops the "16.0."
_OFFICE = ("office", "excel", "word", "outlook", "powerpoint", "onenote", "visio",
           "project", "access", "publisher", "skype", "365")
_BUILD = re.compile(r"^\d+(\.\d+)+$")


def _norm_build(fb: str, product: str):
    """MSRC FixedBuild → a comparable build, or None when it isn't build-matchable.

    - Click-to-Run Office auto-updates → MSRC gives a URL (not a build) → None (dropped;
      C2R has no fixed build to compare, so a build verdict would be a false positive).
    - MSI Office sometimes drops the leading "16.0." (e.g. "5215.1000") → restore it so it
      compares against the scanner's full build (16.0.MMMM.PPPP).
    """
    fb = (fb or "").strip()
    if not _BUILD.match(fb):                       # URL / prose → not a build
        return None
    if fb.count(".") == 1 and any(o in product for o in _OFFICE):
        return "16.0." + fb
    return fb


def _product_cpes(doc: dict) -> dict:
    """ProductID → NVD-validated canonical cpe23, for every CPE-matchable product."""
    out = {}
    for p in (doc.get("ProductTree") or {}).get("FullProductName") or []:
        pid, raw, name = p.get("ProductID"), p.get("CPE"), p.get("Value") or ""
        if not pid or "mariner" in name.lower():        # MS Linux → own distro, not a CPE
            continue
        key = cpe_norm.canonical(raw)[0] if raw else cpe_norm.from_name(name)
        if key:
            out[pid] = key
    return out


def _doc_rows(doc: dict):
    pmap = _product_cpes(doc)
    if not pmap:
        return
    for v in doc.get("Vulnerability") or []:
        cid = normalize(v.get("CVE") or "")
        if not cid:
            continue
        seen = set()
        for r in v.get("Remediations") or []:
            fb_raw = r.get("FixedBuild")
            if not fb_raw:
                continue
            sub = r.get("SubType")
            for pid in r.get("ProductID") or []:
                cpe = pmap.get(pid)
                if not cpe:
                    continue
                fb = _norm_build(fb_raw, cpe.split(":")[4])
                if fb is None:           # URL (C2R auto-update) / non-build → not matchable, drop
                    continue
                key = (cpe, fb)
                if key in seen:
                    continue
                seen.add(key)
                # scope to this build lineage so a different scheme under the same product
                # can't cross-match (e.g. Office-for-Mac 16.55.x vs Windows-Office 16.0.x: a
                # 16.0 host is below the 16.55 `introduced` and is skipped). Releases are keyed
                # by major.minor (Office 16.0, SQL 15.0, Exchange 15.2) — EXCEPT the SQL drivers,
                # whose release line is the major alone (ODBC 17.x, 18.x; .10 is a patch, not a
                # release), so major.minor would wrongly drop e.g. a 17.5 host below a 17.10 fix.
                prod = cpe.split(":")[4]
                n = 1 if ("odbc_driver" in prod or "ole_db_driver" in prod) else 2
                intro = ".".join(fb.split(".")[:n])
                yield row(cve_id=cid, coord="cpe", cpe23=cpe, package=cpe.split(":")[4],
                          introduced=intro, fixed=fb, version_scheme="generic",
                          status=st.FIXED, status_raw=sub,
                          source=SOURCE, status_source="own", origin=ORIGIN)


def extract(conn, dirs):
    cpe_norm.load(conn)
    base = Path(dirs["microsoft"])
    for f in sorted(glob.glob(str(base / "*.json"))):
        try:
            doc = json.loads(Path(f).read_bytes())
        except Exception:
            continue
        yield from _doc_rows(doc)
