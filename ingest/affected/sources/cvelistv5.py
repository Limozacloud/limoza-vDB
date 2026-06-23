"""CVE List → affected (coord=cpe) — the unmanaged / binary lane.

From each CVE record's `containers.cna.affected[]` we take entries that carry a CPE,
and turn their `versions[]` into cpe-coordinate ranges:
    version          → introduced
    lessThan         → fixed         (exclusive upper)
    lessThanOrEqual  → last_affected (inclusive upper)
    bare version     → exact (last_affected = that version)
The CPE is normalised to its vendor:product identity (version field → *); the range
lives in the introduced/fixed columns. status maps affected/unaffected → canonical.
"""
import glob
import json
from pathlib import Path

from ingest.affected import cpe_norm, row
from ingest.affected import status as st

ORIGIN = SOURCE = "cvelistv5"

_VT = {"semver": "semver", "maven": "maven", "rpm": "rpm",
       "python": "pep440", "pep440": "pep440", "git": "git"}
_VAGUE = {"*", "-", "unspecified", "n/a", "na", "unknown", "publication", "various", "all", ""}
_STATUS = {"affected": st.AFFECTED, "unaffected": st.NOT_AFFECTED}


def _norm_cpe(cpe: str):
    """Resolve+validate a CNA-provided CPE against the NVD catalog (cpe_norm); None when
    its (vendor, product) isn't a real NVD CPE. Microsoft is excluded — MSRC is the
    authoritative source for all Microsoft products."""
    p = cpe.split(":")
    if len(p) < 6 or p[0] != "cpe" or p[3].lower() == "microsoft":
        return None
    return cpe_norm.canonical(cpe)[0]


def _clean(v):
    return None if str(v).strip().lower() in _VAGUE else v


def _file_rows(d: dict):
    cid = (d.get("cveMetadata") or {}).get("cveId")
    cna = (d.get("containers") or {}).get("cna") or {}
    if not cid:
        return
    seen = set()
    for a in cna.get("affected") or []:
        cpes = list(dict.fromkeys(c for c in (_norm_cpe(c) for c in (a.get("cpes") or [])) if c))
        if not cpes:
            continue
        default = a.get("defaultStatus")
        scheme_default = _VT.get((a.get("versionType") or "").lower(), "generic")
        for cpe in cpes:
            for v in a.get("versions") or []:
                status = _STATUS.get(v.get("status") or default)
                if not status:
                    continue
                lt_raw, lte_raw = v.get("lessThan"), v.get("lessThanOrEqual")
                lt, lte = _clean(lt_raw), _clean(lte_raw)
                ver = _clean(v.get("version"))
                if lt:
                    intro, fixed, last = ver or "0", lt, None
                elif lte:
                    intro, fixed, last = ver or "0", None, lte
                elif lt_raw or lte_raw:                         # a range was meant but the bound is vague
                    if not ver:                                #   ("publication", …) → open-ended affected
                        continue
                    intro, fixed, last = ver, None, None
                elif ver:
                    intro, fixed, last = ver, None, ver        # bare = exact version
                else:
                    continue
                scheme = _VT.get((v.get("versionType") or "").lower(), scheme_default)
                key = (cpe, intro, fixed, last, status)
                if key in seen:
                    continue
                seen.add(key)
                yield row(cve_id=cid, coord="cpe", cpe23=cpe, package=cpe.split(":")[4],
                          introduced=intro, fixed=fixed, last_affected=last,
                          version_scheme=scheme, status=status,
                          source=SOURCE, status_source="own", origin=ORIGIN)


def extract(conn, dirs):
    cpe_norm.load(conn)
    base = Path(dirs["cvelistv5"]) / "repo" / "cves"
    for f in glob.iglob(str(base / "**" / "CVE-*.json"), recursive=True):
        try:
            d = json.loads(Path(f).read_bytes())
        except Exception:
            continue
        yield from _file_rows(d)
