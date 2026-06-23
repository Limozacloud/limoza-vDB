"""Ubuntu → affected (coord=purl, distro lane).

Re-parses the Ubuntu OSV export (/data/ubuntu/osv/UBUNTU-CVE-*.json), which carries
per-release affected/fixed ranges:
    package.ecosystem  "Ubuntu:22.04:LTS"
    package.purl       pkg:deb/ubuntu/<name>@<ver>?…&distro=<codename>
    ranges[].events    {introduced, fixed}
release = the Ubuntu codename (jammy/noble/trusty…) — what a host reports.
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


def _file_rows(d: dict):
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
            key = (name, release, status, fixed, last)
            if key in seen:
                continue
            seen.add(key)
            yield row(cve_id=cid, coord="purl", ecosystem="deb", package=name, purl=base,
                      release=release, introduced=intro or "0", fixed=fixed, last_affected=last,
                      version_scheme="deb", status=status,
                      source=SOURCE, status_source="own", origin=ORIGIN)


def extract(conn, dirs):
    base = Path(dirs["ubuntu"]) / "osv"
    for f in glob.iglob(str(base / "**" / "*.json"), recursive=True):
        try:
            d = json.loads(Path(f).read_bytes())
        except Exception:
            continue
        yield from _file_rows(d)
