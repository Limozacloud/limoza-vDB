"""Parse the Debian security-tracker JSON.

The tracker is package-keyed: {src_pkg: {CVE: {description, scope, releases:{rel:{status,
fixed_version, urgency}}}}}. We invert it to per-CVE for the cve_* tables; the
per-(package, release) fixed-version status is phase-3 affected (not here).

Debian is not a CNA → no orgId; cve_desc.source stays NULL (origin='debian'),
cve_vendor.source='debian'.
"""
import json

from ingest.core.cveid import normalize

_URANK = {"unimportant": 1, "low": 2, "medium": 3, "high": 4}


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def parse_osv_advisory(d: dict):
    """OSV DSA/DLA/DTSA entry → (advisory_id, title, published, modified, [cve_ids]).
    The CVE links are in `upstream` (alongside DEBIAN-CVE-* which normalize() drops)."""
    aid = d.get("id")
    if not aid:
        return None
    cves = [c for c in (normalize(u) for u in (d.get("upstream") or [])) if c]
    return (aid, d.get("summary"), d.get("published"), d.get("modified"), cves)


def invert(d: dict) -> dict:
    """package-keyed tracker → {cve_id: {desc, scope, urgency}} (urgency = highest seen)."""
    per: dict = {}
    for cves in d.values():
        for cid_raw, info in cves.items():
            cid = normalize(cid_raw)
            if not cid:
                continue
            e = per.setdefault(cid, {"desc": None, "scope": None, "urgency": None, "_rank": 0})
            if not e["desc"] and info.get("description"):
                e["desc"] = info["description"].strip()
            if not e["scope"] and info.get("scope"):
                e["scope"] = info["scope"]
            for r in (info.get("releases") or {}).values():
                u = r.get("urgency")
                rk = _URANK.get((u or "").split()[0], 0) if u else 0
                if rk > e["_rank"]:
                    e["_rank"], e["urgency"] = rk, u
    return per
