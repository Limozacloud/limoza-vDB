"""Parse an NVD CVE 2.0 record into a flat structured dict (desc/cvss/cwe/ref).

NVD adds its own enrichment to each CVE — descriptions, CVSS metrics (v2/v3.0/v3.1/v4),
CWE weaknesses and references. We do NOT touch cve_record (the spine record owned by
cvelistv5/MITRE: assigner, title, dates) — NVD only contributes the multi-source info
tables tagged origin='nvd'.
"""
import json

from ingest.core.cveid import normalize


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def _cvss(metrics, out):
    # metrics = {"cvssMetricV31":[...], "cvssMetricV30":[...], "cvssMetricV2":[...], "cvssMetricV40":[...]}
    for key, arr in (metrics or {}).items():
        if not key.startswith("cvssMetric"):
            continue
        for m in arr or []:
            data = m.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            ver = data.get("version") or key.replace("cvssMetricV", "").replace("_", ".")
            sev = (data.get("baseSeverity") or m.get("baseSeverity") or "").lower() or None
            out.append((ver, float(score), sev, data.get("vectorString")))


def _cwe(weaknesses, out):
    for w in weaknesses or []:
        for d in w.get("description") or []:
            cid = (d.get("value") or "").strip()
            if cid.upper().startswith("CWE-"):
                out.append(cid)


def _refs(references, out):
    for r in references or []:
        url = r.get("url")
        if not url:
            continue
        tags = r.get("tags") or []
        out.append((url, tags[0] if tags else None))


def _descs(descriptions, out):
    for d in descriptions or []:
        val = (d.get("value") or "").strip()
        if val:
            out.append((d.get("lang") or "en", val))


def transform(doc: dict) -> dict | None:
    cve = doc.get("cve", doc)            # accept {"cve": {...}} or the bare cve object
    cve_id = normalize(cve.get("id", ""))
    if not cve_id:
        return None
    cvss, cwe, desc, ref = [], [], [], []
    _cvss(cve.get("metrics"), cvss)
    _cwe(cve.get("weaknesses"), cwe)
    _refs(cve.get("references"), ref)
    _descs(cve.get("descriptions"), desc)
    return {"cve_id": cve_id, "cvss": cvss, "cwe": cwe, "desc": desc, "ref": ref}
