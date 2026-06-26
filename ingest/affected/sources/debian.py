"""Debian → affected (coord=purl, distro lane).

Parses the Debian Security Tracker (/data/debian/tracker.json), the richest distro
source — full per-package per-release status:
    { <src-package>: { <CVE>: { releases: { <codename>: {status, fixed_version, urgency, nodsa, nodsa_reason} } } } }

status mapping (justification carries the "why"; status_raw keeps the tracker's raw status):
    resolved + real fixed_version → fixed (that version)
    resolved + fixed_version "0"  → not_affected (release ships a safe version)
    open:
        nodsa set (any reason)    → wont_fix  (Debian decided no security advisory — ignored,
                                               postponed, or minor; all deprioritised)
        urgency "unimportant"     → wont_fix  (minor)
        urgency "end-of-life"     → wont_fix  (release/package EOL)
        else                      → affected  (open, no fix yet — incl. untriaged "not yet assigned")
    undetermined                  → unknown
release = the Debian codename (bookworm/bullseye/trixie/sid).
"""
import json
from pathlib import Path

from ingest.affected import row
from ingest.affected import status as st
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "debian"


def _status(st_raw, fixed_version, urgency, nodsa, nodsa_reason):
    """→ (status, fixed_version_or_None, justification). See module docstring for the ruleset."""
    if st_raw == "resolved":
        if fixed_version and fixed_version != "0":
            return st.FIXED, fixed_version, None
        return st.NOT_AFFECTED, None, "not affected in release"   # ships a safe version
    if st_raw == "open":
        if nodsa:                                                 # any no-dsa decision → deprioritised
            return st.WONT_FIX, None, f"nodsa: {nodsa_reason or 'no advisory'}"
        if urgency in ("unimportant", "end-of-life"):
            return st.WONT_FIX, None, f"urgency: {urgency}"
        return st.AFFECTED, None, None
    return st.UNKNOWN, None, None


def extract(conn, dirs):
    data = json.loads((Path(dirs["debian"]) / "tracker.json").read_text())
    for pkg, cves in data.items():
        base = f"pkg:deb/debian/{pkg}"
        for rawcve, info in cves.items():
            cid = normalize(rawcve)
            if not cid:
                continue
            for rel, r in (info.get("releases") or {}).items():
                status, fixed, just = _status(r.get("status"), r.get("fixed_version"),
                                              r.get("urgency"), r.get("nodsa"), r.get("nodsa_reason"))
                yield row(cve_id=cid, coord="purl", ecosystem="deb", package=pkg, purl=base,
                          release=rel, introduced="0", fixed=fixed, version_scheme="deb",
                          status=status, status_raw=r.get("status"), justification=just,
                          source=SOURCE, status_source="own", origin=ORIGIN)
