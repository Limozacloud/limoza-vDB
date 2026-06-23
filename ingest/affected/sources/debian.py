"""Debian → affected (coord=purl, distro lane).

Parses the Debian Security Tracker (/data/debian/tracker.json), the richest distro
source — full per-package per-release status:
    { <src-package>: { <CVE>: { releases: { <codename>: {status, fixed_version, urgency} } } } }
status mapping:
    open                         → affected (urgency end-of-life → wont_fix)
    resolved + real fixed_version → fixed (that version)
    resolved + fixed_version "0"  → not_affected (release ships a safe version)
    undetermined                  → unknown
release = the Debian codename (bookworm/bullseye/trixie/sid).
"""
import json
from pathlib import Path

from ingest.affected import row
from ingest.affected import status as st
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "debian"


def _status(st_raw, fixed_version, urgency):
    if st_raw == "open":
        return (st.WONT_FIX if urgency == "end-of-life" else st.AFFECTED), None
    if st_raw == "resolved":
        if fixed_version and fixed_version != "0":
            return st.FIXED, fixed_version
        return st.NOT_AFFECTED, None          # ships a safe version
    return st.UNKNOWN, None


def extract(conn, dirs):
    data = json.loads((Path(dirs["debian"]) / "tracker.json").read_text())
    for pkg, cves in data.items():
        base = f"pkg:deb/debian/{pkg}"
        for rawcve, info in cves.items():
            cid = normalize(rawcve)
            if not cid:
                continue
            for rel, r in (info.get("releases") or {}).items():
                status, fixed = _status(r.get("status"), r.get("fixed_version"), r.get("urgency"))
                yield row(cve_id=cid, coord="purl", ecosystem="deb", package=pkg, purl=base,
                          release=rel, introduced="0", fixed=fixed, version_scheme="deb",
                          status=status, status_raw=r.get("status"),
                          source=SOURCE, status_source="own", origin=ORIGIN)
