"""SUSE CSAF VEX → affected (coord=purl, full VEX status).

Same CSAF shape as Red Hat but SUSE-specific details:
  - product_status buckets: known_affected / known_not_affected / first_fixed /
    recommended / under_investigation (no plain "fixed"; first_fixed+recommended = fixed)
  - product_ids are long human names ("SUSE Linux … 15 SP7:<pkg>")
  - release lives in the platform CPE (cpe:/o:suse:sles:15:sp7 → "sles15sp7")
  - no purl helpers and no VEX flags → purl constructed, justification = None

Per file we de-duplicate to one row per (package, release, status, fixed).
"""
import glob
import json
import re
from pathlib import Path

from ingest.affected import row
from ingest.affected import status as st
from ingest.affected.sources.redhat import _index_tree    # same product_tree structure

ORIGIN = SOURCE = "suse"

_SUSE_CPE = re.compile(r"cpe:/[ao]:(?:open)?suse:([^:]+)(?::([^:]+))?(?::sp(\d+))?", re.I)


def _release(cpe: str | None):
    """cpe:/o:suse:sles:15:sp7 → 'sles15sp7' ; cpe:/o:opensuse:leap:15.6 → 'leap15.6'
    ; cpe:/o:opensuse:tumbleweed → 'tumbleweed'."""
    if not cpe:
        return None
    m = _SUSE_CPE.search(cpe)
    if not m:
        return None
    prod, ver, sp = m.group(1), m.group(2), m.group(3)
    return prod + (ver or "") + (f"sp{sp}" if sp else "")


def _split_nvr(s: str):
    """'cluster-md-kmp-default-6.4.0-150700.53.34.1' → ('cluster-md-kmp-default',
    '6.4.0-150700.53.34.1') ; 'kernel-source-azure' → ('kernel-source-azure', None)."""
    m = re.match(r"^(.+?)-(\d.*)$", s)
    return (m.group(1), m.group(2)) if m else (s, None)


def _resolve(pid, cpe_by_id, rel):
    pkg_ref, plat_ref = rel.get(pid, (None, None))
    if pkg_ref is None:
        if ":" in pid:
            plat_ref, pkg_ref = pid.split(":", 1)
        else:
            pkg_ref = pid
    name, ver = _split_nvr(pkg_ref) if pkg_ref else (None, None)
    return name, _release(cpe_by_id.get(plat_ref)), (f"pkg:rpm/suse/{name}" if name else None), ver


def _file_rows(d: dict):
    vulns = d.get("vulnerabilities") or []
    if not vulns:
        return
    v = vulns[0]
    from ingest.core.cveid import normalize
    cid = normalize(v.get("cve") or "")
    if not cid:
        return
    raw = v.get("product_status") or {}
    fixed = set(raw.get("first_fixed") or []) | set(raw.get("recommended") or []) | set(raw.get("fixed") or [])
    aff   = set(raw.get("known_affected") or [])
    nota  = set(raw.get("known_not_affected") or [])
    inv   = set(raw.get("under_investigation") or [])

    cpe_by_id, _purl, rel = _index_tree(d.get("product_tree") or {})

    seen = set()
    for pid, status in ([(p, st.FIXED) for p in fixed] + [(p, st.NOT_AFFECTED) for p in nota]
                        + [(p, st.AFFECTED) for p in aff] + [(p, st.UNDER_INVESTIGATION) for p in inv]):
        name, release, base, ver = _resolve(pid, cpe_by_id, rel)
        if not name:
            continue
        fx = ver if status == st.FIXED else None
        key = (name, release, status, fx)
        if key in seen:
            continue
        seen.add(key)
        yield row(cve_id=cid, coord="purl", ecosystem="rpm", package=name, purl=base,
                  release=release, introduced="0", fixed=fx, version_scheme="rpm",
                  status=status, source=SOURCE, status_source="own", origin=ORIGIN)


def extract(conn, dirs):
    base = Path(dirs["suse"]) / "vex"
    for f in glob.iglob(str(base / "**" / "cve-*.json"), recursive=True):
        if not f.endswith(".json"):
            continue
        try:
            d = json.loads(Path(f).read_bytes())
        except Exception:
            continue
        yield from _file_rows(d)
