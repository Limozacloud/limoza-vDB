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
from pathlib import Path

from ingest.affected import cpe_norm, row
from ingest.affected import status as st
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "microsoft"


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
            fb = r.get("FixedBuild")
            if not fb:
                continue
            sub = r.get("SubType")
            for pid in r.get("ProductID") or []:
                cpe = pmap.get(pid)
                if not cpe:
                    continue
                key = (cpe, fb)
                if key in seen:
                    continue
                seen.add(key)
                yield row(cve_id=cid, coord="cpe", cpe23=cpe, package=cpe.split(":")[4],
                          fixed=fb, version_scheme="generic",
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
