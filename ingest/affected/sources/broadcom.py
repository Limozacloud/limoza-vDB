"""Broadcom (VMware) advisories → affected (coord=cpe).

The Response Matrix of each advisory page names the affected version line(s) and the fixed version:

    VMware Tools | 12.x.x, 11.x.x | Windows, Linux | CVE-2025-41244 | 12.5.4
    → cpe:2.3:a:vmware:tools, introduced 11, fixed 12.5.4

NVD lists only open_vm_tools for these CVEs and the CNA records name the product inconsistently with
wildcard versions, so this is the version-precise source for VMware Tools. Rows with a fixed version that
is not a version (Unaffected, KB numbers, Patch Pending), products without a mapping and rows that run
only on Linux/macOS are skipped. The rows coexist with NVD's (the matcher ORs the lanes).
"""
import json
from pathlib import Path

from ingest.advisories.broadcom.matrix import fixed_version, lower_bound, parse_matrices
from ingest.affected import cpe_norm, row
from ingest.affected import status as st

ORIGIN = SOURCE = "broadcom"

# matrix product / component name (lower case) → NVD vendor:product. Extend per product after checking
# that its fixed versions are plain versions.
_PRODUCTS = {
    "vmware tools": ("vmware", "tools"),
    "vmware workstation": ("vmware", "workstation"),
    "vmware workstation pro": ("vmware", "workstation"),
}


def _product(r):
    for name in (r["component"], r["product"]):
        hit = _PRODUCTS.get(name.lower())
        if hit:
            return hit
    return None


def _same(version: str) -> tuple:
    """13.0.5 and 13.0.5.0 are one version: compare without trailing zeros."""
    parts = [int(x) for x in version.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _applies_to_windows(running_on: str) -> bool:
    low = running_on.lower()
    return "windows" in low or "any" in low


def extract(conn, dirs):
    cpe_norm.load(conn)
    base = Path(dirs["broadcom"])
    idx_file = base / "index.json"
    if not idx_file.exists():
        return
    seen = set()
    for k in sorted(json.loads(idx_file.read_bytes())):
        page = base / "advisories" / f"{k}.html"
        if not page.exists():
            continue
        for r in parse_matrices(page.read_text(encoding="utf-8", errors="replace")):
            prod = _product(r)
            fixed, intro = fixed_version(r["fixed"]), lower_bound(r["version"])
            if not prod or not fixed or intro is None or not _applies_to_windows(r["running_on"]):
                continue
            cpe = cpe_norm.canonical(f"cpe:2.3:a:{prod[0]}:{prod[1]}:*:*:*:*:*:*:*:*")[0]
            if not cpe:
                continue
            for cid in r["cves"]:
                key = (cid, cpe, _same(intro), _same(fixed))
                if key in seen:
                    continue
                seen.add(key)
                yield row(cve_id=cid, coord="cpe", cpe23=cpe, package=prod[1], introduced=intro, fixed=fixed,
                          version_scheme="generic", status=st.FIXED, source=SOURCE, status_source="own",
                          origin=ORIGIN)
