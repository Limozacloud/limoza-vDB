"""Ubuntu → affected (coord=purl, distro lane).

Re-parses the Ubuntu OSV export (/data/ubuntu/osv/UBUNTU-CVE-*.json), which carries
per-release affected/fixed ranges:
    package.ecosystem  "Ubuntu:22.04:LTS"
    package.purl       pkg:deb/ubuntu/<name>@<ver>?…&distro=<codename>
    ranges[].events    {introduced, fixed}
release = the Ubuntu codename (jammy/noble/trusty…) — what a host reports.

The OSV export only knows affected/fixed. We overlay the OpenVEX export (vex/cve/) to
downgrade the deprioritised rows: where Ubuntu's VEX marks a package affected but its
action_statement says "no longer supported" (EOL) or "decided to not fix" (ignored/deferred),
the row becomes wont_fix (with justification) so it drops out of the vulnerable verdict.
"""
import glob
import json
from pathlib import Path

from ingest.affected import row
from ingest.affected import status as st
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "ubuntu"


def _cve(d):
    # OSV id is "UBUNTU-CVE-2012-6541" → strip the UBUNTU- prefix; aliases as fallback
    for a in [(d.get("id") or "").replace("UBUNTU-", "")] + (d.get("aliases") or []):
        c = normalize(a or "")
        if c:
            return c
    return None


def _release(purl: str, eco: str):
    for kv in (purl.split("?", 1)[1].split("&") if "?" in purl else []):
        if kv.startswith("distro="):
            return kv.split("=", 1)[1]
    parts = (eco or "").split(":")           # "Ubuntu:22.04:LTS"
    return f"ubuntu{parts[1]}" if len(parts) >= 2 else None


def _vex_purl(pid: str):
    """pkg:deb/ubuntu/<name>@<ver>?…&distro=<codename> → (name, codename)."""
    if "pkg:deb/ubuntu/" not in pid:
        return None, None
    body = pid.split("pkg:deb/ubuntu/", 1)[1]
    name = body.split("@", 1)[0].split("?", 1)[0]
    rel = None
    if "?" in pid:
        for kv in pid.split("?", 1)[1].split("&"):
            if kv.startswith("distro="):
                rel = kv.split("=", 1)[1]
    return (name or None), rel


def _load_vex(vexdir: Path):
    """OpenVEX → {(cve, package, release): justification} for affected-but-won't-fix.

    OpenVEX's `status` only carries affected/fixed/not_affected; Ubuntu encodes the won't-fix
    nuance in the `action_statement` template text. We map only that nuance — the OSV export
    already supplies affected/fixed, this overlay just downgrades the deprioritised ones.
    """
    m = {}
    if not vexdir.exists():
        return m
    for f in glob.iglob(str(vexdir / "**" / "CVE-*.json"), recursive=True):
        try:
            d = json.loads(Path(f).read_bytes())
        except Exception:
            continue
        for s in d.get("statements") or []:
            if s.get("status") != "affected":
                continue
            act = (s.get("action_statement") or "").lower()
            if "no longer supported" in act:
                reason = "end of support"
            elif "decided to not" in act or "will not be" in act:
                reason = "ignored/deferred"
            else:
                continue
            cid = (s.get("vulnerability") or {}).get("name")
            if not cid:
                continue
            for p in s.get("products") or []:
                pid = p.get("@id") or ""
                if "arch=source" not in pid:          # OSV is source-keyed → only need source rows
                    continue
                name, rel = _vex_purl(pid)
                if name and rel:
                    m[(cid, name, rel)] = reason
    return m


def _file_rows(d: dict, vex: dict):
    cid = _cve(d)
    if not cid:
        return
    seen = set()
    for af in d.get("affected") or []:
        pkg = af.get("package") or {}
        name = pkg.get("name")
        if not name:
            continue
        release = _release(pkg.get("purl") or "", pkg.get("ecosystem") or "")
        base = f"pkg:deb/ubuntu/{name}"
        ranges = af.get("ranges") or []
        if not ranges:
            ranges = [None]
        for r in ranges:
            intro = fixed = last = None
            for e in (r or {}).get("events", []):
                if e.get("introduced") and e["introduced"] != "0":
                    intro = e["introduced"]
                if e.get("fixed"):
                    fixed = e["fixed"]
                if e.get("last_affected"):
                    last = e["last_affected"]
            status = st.FIXED if fixed else st.AFFECTED
            just = None
            if status == st.AFFECTED:                          # VEX overlay: downgrade won't-fix
                reason = vex.get((cid, name, release))
                if reason:
                    status, just = st.WONT_FIX, reason
            key = (name, release, status, fixed, last)
            if key in seen:
                continue
            seen.add(key)
            yield row(cve_id=cid, coord="purl", ecosystem="deb", package=name, purl=base,
                      release=release, introduced=intro or "0", fixed=fixed, last_affected=last,
                      version_scheme="deb", status=status, justification=just,
                      source=SOURCE, status_source="own", origin=ORIGIN)


def extract(conn, dirs):
    root = Path(dirs["ubuntu"])
    vex = _load_vex(root / "vex" / "cve")
    print(f"  ubuntu: {len(vex):,} VEX won't-fix overlays loaded", flush=True)
    base = root / "osv"
    for f in glob.iglob(str(base / "**" / "*.json"), recursive=True):
        try:
            d = json.loads(Path(f).read_bytes())
        except Exception:
            continue
        yield from _file_rows(d, vex)
