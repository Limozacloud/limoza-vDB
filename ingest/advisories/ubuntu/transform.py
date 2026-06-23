"""Parse Ubuntu security data (canonical/ubuntu-security-notices).

  osv/cve/UBUNTU-CVE-*.json — per-CVE: details (desc), CVSS vectors, Ubuntu priority.
                              Ubuntu gives the CVSS VECTOR but no base score → we compute it.
  usn/*.json                — per-USN advisory: id, title, timestamp, cves[].
"""
import json
from datetime import datetime, timezone

from ingest.core.cveid import normalize
from ingest.core.cvss import score_from_vector, severity_from_score


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def transform_osv(d: dict, source) -> dict | None:
    cve_id = None
    for a in d.get("aliases") or []:
        cid = normalize(a)
        if cid:
            cve_id = cid
            break
    if not cve_id:
        cve_id = normalize((d.get("id") or "").replace("UBUNTU-", ""))
    if not cve_id:
        return None

    cvss, seen = [], set()
    priority = None
    for s in d.get("severity") or []:
        t, sc = s.get("type"), (s.get("score") or "")
        if t in ("CVSS_V3", "CVSS_V4", "CVSS_V2") and sc.startswith("CVSS") and sc not in seen:
            seen.add(sc)
            ver, score = score_from_vector(sc)            # compute base score from vector
            if score is not None:
                cvss.append((source, ver, score, severity_from_score(score, ver), sc))
        elif t == "Ubuntu" and sc:
            priority = sc                                  # Ubuntu's own rating

    desc = []
    det = (d.get("details") or "").strip()
    if det:
        desc.append((source, "en", det))

    vd = {}
    if priority:
        vd["severity"] = priority

    return {"cve_id": cve_id, "cvss": cvss, "desc": desc, "vendor_data": vd}


def parse_usn(d: dict):
    """USN json → (usn_id, title, published_iso, [cve_ids])."""
    uid = d.get("id")
    if not uid:
        return None
    ts = d.get("timestamp")
    if isinstance(ts, (int, float)):
        pub = datetime.fromtimestamp(ts, timezone.utc).isoformat()
    elif isinstance(ts, str):
        pub = ts
    else:
        pub = None
    cves = [c for c in (normalize(x) for x in (d.get("cves") or [])) if c]
    return (uid, d.get("title"), pub, cves)
