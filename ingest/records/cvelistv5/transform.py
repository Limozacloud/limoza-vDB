"""Parse a CVE Record v5.x JSON into a flat structured dict.

Pulls from cveMetadata + containers.cna + containers.adp[]. The CNA container is
tagged source='cna'; each ADP container by its provider shortName (e.g.
'cisa-adp'). Returns None for records without a usable CVE id.
"""
import json
import re

from ingest.core.cveid import normalize
from ingest.core.cvss import severity_from_score


def _clean_text(v):
    """Tidy the CNA's often-sloppy plaintext value: trim, collapse blank-line runs."""
    v = (v or "").strip()
    return re.sub(r"\n{3,}", "\n\n", v)


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def _cvss(metrics, source, out):
    for m in metrics or []:
        for key, d in m.items():
            if not key.startswith("cvssV") or not isinstance(d, dict):
                continue
            score = d.get("baseScore")
            if score is None:
                continue
            ver = d.get("version") or key.replace("cvssV", "").replace("_", ".")
            sev = d.get("baseSeverity")
            sev = sev.lower() if sev else severity_from_score(score, ver)
            out.append((source, ver, float(score), sev, d.get("vectorString")))


def _cwe(problem_types, source, out):
    for pt in problem_types or []:
        for d in pt.get("descriptions", []) or []:
            cid = d.get("cweId")
            if cid:
                out.append((source, cid))


def _refs(references, source, out):
    for r in references or []:
        url = r.get("url")
        if not url:
            continue
        tags = r.get("tags") or []
        out.append((source, url, tags[0] if tags else None))


def _descs(descriptions, source, out):
    for d in descriptions or []:
        val = _clean_text(d.get("value"))
        if val:
            out.append((source, d.get("lang") or "en", val))


def _impacts(impacts, source, out):
    for im in impacts or []:
        descs = im.get("descriptions") or []
        out.append((source, im.get("capecId"), descs[0].get("value") if descs else None))


def transform(doc: dict) -> dict | None:
    meta = doc.get("cveMetadata", {})
    cve_id = normalize(meta.get("cveId", ""))
    if not cve_id:
        return None

    containers = doc.get("containers", {})
    cna = containers.get("cna", {}) or {}
    adps = containers.get("adp", []) or []

    cvss, cwe, desc, ref, sol, wrk, imp = [], [], [], [], [], [], []

    # source on every cve_* row = the authoring org's orgId UUID (stable), so it
    # joins to cna.uuid (CNA scorers) or adp.uuid (ADP scorers). The assigner
    # shortName is returned separately for the cve_record owner (→ cna_id).
    cna_pm   = cna.get("providerMetadata", {})
    cna_uuid = cna_pm.get("orgId")
    cna_src  = cna_uuid or meta.get("assignerShortName") or "unknown"   # source is NOT NULL
    _cvss(cna.get("metrics"), cna_src, cvss)
    _cwe(cna.get("problemTypes"), cna_src, cwe)
    _refs(cna.get("references"), cna_src, ref)
    _descs(cna.get("descriptions"), cna_src, desc)
    _descs(cna.get("rejectedReasons"), cna_src, desc)   # rejected records
    _descs(cna.get("solutions"), cna_src, sol)
    _descs(cna.get("workarounds"), cna_src, wrk)
    _impacts(cna.get("impacts"), cna_src, imp)

    exploit_note = _clean_text(next((e["value"] for e in (cna.get("exploits") or []) if e.get("value")), "")) or None

    # ADP containers (CISA-ADP vulnrichment, NVD-as-ADP, …) — tag by ADP orgId UUID
    adp_orgs = []
    for adp in adps:
        pm  = adp.get("providerMetadata", {})
        uid = pm.get("orgId")
        if uid:
            adp_orgs.append((uid, pm.get("shortName"), pm.get("dateUpdated")))
        src = uid or pm.get("shortName") or "unknown"   # source is NOT NULL
        _cvss(adp.get("metrics"), src, cvss)
        _cwe(adp.get("problemTypes"), src, cwe)
        _refs(adp.get("references"), src, ref)
        _descs(adp.get("descriptions"), src, desc)
        _descs(adp.get("solutions"), src, sol)
        _descs(adp.get("workarounds"), src, wrk)
        _impacts(adp.get("impacts"), src, imp)

    return {
        "cve_id":         cve_id,
        "state":          meta.get("state"),
        "assigner":       meta.get("assignerShortName"),
        "assigner_uuid":  cna_uuid,
        "adps":           adp_orgs,
        "date_reserved":  meta.get("dateReserved"),
        "date_published": meta.get("datePublished"),
        "date_updated":   meta.get("dateUpdated"),
        "title":          cna.get("title"),
        "exploit_note":   exploit_note,
        "cvss":           cvss,
        "cwe":            cwe,
        "desc":           desc,
        "ref":            ref,
        "solution":       sol,
        "workaround":     wrk,
        "impact":         imp,
    }
