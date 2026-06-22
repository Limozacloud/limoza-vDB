"""Parse a RedHat CSAF VEX file (cve-*.json) into flat rows.

VEX is per-CVE. We pull RedHat's enrichment (cvss/cwe/refs/workaround/impact),
the RHSA references (vendor_fix remediations), and the per-CVE vendor assessment
(aggregate_severity). Product status / fixed versions are phase 3, not here.

Returns lists shaped to match the cve_* tables (source is prepended in ingest):
  cvss       (source, version, base_score, severity, vector)
  cwe        (source, cwe_id)
  ref        (source, url, type)
  workaround (source, lang, value)
  impact     (source, capec_id, description)
plus rhsa {advisory_id: url} and vendor_data {}.
"""
import json

from ingest.core.cveid import normalize
from ingest.core.cvss import severity_from_score

_ADV_PREFIXES = ("RHSA-", "RHBA-", "RHEA-")


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def _rhsa_id(url: str):
    seg = url.rstrip("/").rsplit("/", 1)[-1]          # …/errata/RHSA-2024:2011 → RHSA-2024:2011
    return seg if seg.startswith(_ADV_PREFIXES) else None


def transform(d: dict, source) -> dict | None:
    vulns = d.get("vulnerabilities") or []
    if not vulns:
        return None
    v = vulns[0]
    cve_id = normalize(v.get("cve") or "")
    if not cve_id:
        return None

    # CVSS — CSAF scores[].cvss_v3 / cvss_v2
    cvss = []
    for s in v.get("scores") or []:
        for key, default_ver in (("cvss_v3", "3.1"), ("cvss_v2", "2.0")):
            c = s.get(key)
            if isinstance(c, dict) and c.get("baseScore") is not None:
                ver = c.get("version") or default_ver
                sev = c.get("baseSeverity")
                sev = sev.lower() if sev else severity_from_score(c["baseScore"], ver)
                cvss.append((source, ver, float(c["baseScore"]), sev, c.get("vectorString")))

    # CWE — single object
    cwe = []
    cw = v.get("cwe") or {}
    if cw.get("id"):
        cwe.append((source, cw["id"]))

    # references
    ref, seen_url = [], set()
    for r in v.get("references") or []:
        u = r.get("url")
        if u and u not in seen_url:
            seen_url.add(u)
            ref.append((source, u, r.get("category")))

    # remediations → workarounds (joined) + RHSA advisories + solution (vendor_fix details)
    wtexts, rhsa, sol_text = [], {}, None
    for rem in v.get("remediations") or []:
        cat = rem.get("category")
        if cat in ("workaround", "mitigation"):
            txt = (rem.get("details") or "").strip()
            if txt and txt not in wtexts:
                wtexts.append(txt)
        elif cat == "vendor_fix":
            if rem.get("url"):
                aid = _rhsa_id(rem["url"])
                if aid:
                    rhsa[aid] = rem["url"]
            if sol_text is None and (rem.get("details") or "").strip():
                sol_text = rem["details"].strip()
    workaround = [(source, "en", "\n\n".join(wtexts))] if wtexts else []
    solution = [(source, "en", sol_text)] if sol_text else []

    # description note → cve_desc (RedHat's wording)
    desc = []
    for n in v.get("notes") or []:
        if n.get("category") == "description" and (n.get("text") or "").strip():
            desc.append((source, "en", n["text"].strip()))
            break

    # RedHat's impact is a qualitative severity word (not a CAPEC attack impact),
    # so it belongs in the vendor blob, NOT cve_impact (which is for CAPEC).
    impact = []

    # per-CVE vendor assessment → cve_vendor.data (RedHat-specific, unstructured)
    doc = d.get("document", {})
    vendor_data = {}
    sev = (doc.get("aggregate_severity") or {}).get("text")
    if sev:
        vendor_data["severity"] = sev
    for t in v.get("threats") or []:
        if t.get("category") == "impact" and (t.get("details") or "").strip():
            vendor_data["impact"] = t["details"].strip()
            break
    for n in v.get("notes") or []:
        if (n.get("title") or "").strip().lower() == "statement" and (n.get("text") or "").strip():
            vendor_data["statement"] = n["text"].strip()
            break
    for idx in v.get("ids") or []:
        if "bugzilla" in (idx.get("system_name") or "").lower() and idx.get("text"):
            vendor_data["bugzilla"] = idx["text"]
            break
    if v.get("discovery_date"):
        vendor_data["discovery_date"] = v["discovery_date"]

    return {
        "cve_id": cve_id,
        "cvss": cvss, "cwe": cwe, "ref": ref, "desc": desc,
        "workaround": workaround, "solution": solution, "impact": impact,
        "rhsa": rhsa, "vendor_data": vendor_data,
    }


def parse_advisory(d: dict):
    """Pull RHSA-object metadata from an advisories-feed CSAF file (rhsa-*.json).
    Returns (advisory_id, title, severity, published, modified, url) or None."""
    doc = d.get("document", {})
    aid = (doc.get("tracking", {}) or {}).get("id")
    if not aid:
        return None
    sev = (doc.get("aggregate_severity") or {}).get("text")
    tr  = doc.get("tracking", {}) or {}
    url = None
    for r in doc.get("references", []) or []:
        if r.get("category") == "self" and r.get("url"):
            url = r["url"]
            break
    return (aid, doc.get("title"), sev,
            tr.get("initial_release_date"), tr.get("current_release_date"), url)

