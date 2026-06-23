"""Parse SUSE CSAF files.

Two kinds, both CSAF:
  VEX (csaf-vex/cve-*.json)     — per-CVE: severity, cvss, cwe, refs, desc.
                                  SUSE VEX has NO vendor_fix url → no advisory refs here.
  advisory (csaf/*-su-*.json)   — per-SUSE-SU: title/severity/dates + the CVEs it fixes.
                                  THIS is where advisory_cve comes from (unlike RedHat).
"""
import json

from ingest.core.cveid import normalize
from ingest.core.cvss import severity_from_score


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def transform_vex(d: dict, source) -> dict | None:
    vulns = d.get("vulnerabilities") or []
    if not vulns:
        return None
    v = vulns[0]
    cve_id = normalize(v.get("cve") or "")
    if not cve_id:
        return None
    doc = d.get("document", {})

    cvss = []
    for s in v.get("scores") or []:
        for key, default_ver in (("cvss_v3", "3.1"), ("cvss_v2", "2.0")):
            c = s.get(key)
            if isinstance(c, dict) and c.get("baseScore") is not None:
                ver = c.get("version") or default_ver
                sev = c.get("baseSeverity")
                sev = sev.lower() if sev else severity_from_score(c["baseScore"], ver)
                cvss.append((source, ver, float(c["baseScore"]), sev, c.get("vectorString")))

    cwe = []
    cw = v.get("cwe") or {}
    if cw.get("id"):
        cwe.append((source, cw["id"]))

    ref, seen = [], set()
    for r in v.get("references") or []:
        u = r.get("url")
        if u and u not in seen:
            seen.add(u)
            ref.append((source, u, r.get("category")))

    # SUSE puts the CVE description in a 'general' note
    desc = []
    for n in v.get("notes") or []:
        if n.get("category") in ("general", "description") and (n.get("text") or "").strip():
            desc.append((source, "en", n["text"].strip()))
            break

    wtexts = []
    for rem in v.get("remediations") or []:
        if rem.get("category") in ("workaround", "mitigation"):
            t = (rem.get("details") or "").strip()
            if t and t not in wtexts:
                wtexts.append(t)
    workaround = [(source, "en", "\n\n".join(wtexts))] if wtexts else []

    vd = {}
    sev = (doc.get("aggregate_severity") or {}).get("text")
    if sev:
        vd["severity"] = sev
    for t in v.get("threats") or []:
        if t.get("category") == "impact" and (t.get("details") or "").strip():
            vd["impact"] = t["details"].strip()
            break

    return {
        "cve_id": cve_id,
        "cvss": cvss, "cwe": cwe, "ref": ref, "desc": desc,
        "solution": [], "workaround": workaround, "impact": [],
        "vendor_data": vd,
    }


def parse_advisory(d: dict):
    """SUSE-SU CSAF → (advisory_id, title, severity, published, modified, url, [cve_ids])."""
    doc = d.get("document", {})
    tr  = doc.get("tracking", {}) or {}
    aid = tr.get("id")
    if not aid:
        return None
    sev = (doc.get("aggregate_severity") or {}).get("text")
    url = next((r.get("url") for r in doc.get("references", []) or []
                if r.get("category") == "self" and r.get("url")), None)
    cves = []
    for v in d.get("vulnerabilities") or []:
        c = normalize(v.get("cve") or "")
        if c:
            cves.append(c)
    return (aid, doc.get("title"), sev,
            tr.get("initial_release_date"), tr.get("current_release_date"), url, cves)
