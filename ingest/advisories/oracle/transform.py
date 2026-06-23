"""Parse Oracle Linux OVAL definitions (ELSA errata).

Each definition = one ELSA: metadata.title, references (elsa + CVEs),
advisory.severity/issued, and advisory.cve elements carrying a cvss3 attribute
of the form "<score>/<vector>". Per-package fix tests = phase-3 affected.
"""
from ingest.core.cveid import normalize


def lt(e) -> str:
    return e.tag.split("}")[-1]


def _find(p, name):
    return next((c for c in p if lt(c) == name), None)


def _findall(p, name):
    return [c for c in p if lt(c) == name]


def parse_definition(defn) -> dict | None:
    meta = _find(defn, "metadata")
    if meta is None:
        return None
    te = _find(meta, "title")
    title = (te.text or "").strip() if te is not None else ""

    elsa_id = None
    for r in _findall(meta, "reference"):
        if (r.get("source") or "").lower() == "elsa":
            elsa_id = r.get("ref_id")
            break
    if not elsa_id and ":" in title:
        elsa_id = title.split(":", 1)[0].strip()

    adv = _find(meta, "advisory")
    severity = issued = None
    cves = []
    if adv is not None:
        s = _find(adv, "severity")
        severity = (s.text or "").strip() if s is not None and s.text else None
        iss = _find(adv, "issued")
        issued = iss.get("date") if iss is not None else None
        for c in _findall(adv, "cve"):
            cid = normalize(c.text or "")
            if cid:
                cves.append((cid, c.get("cvss3")))
    if not cves:                                   # fallback: CVE references
        for r in _findall(meta, "reference"):
            if (r.get("source") or "").upper() == "CVE":
                cid = normalize(r.get("ref_id") or "")
                if cid:
                    cves.append((cid, None))

    return {"elsa_id": elsa_id, "title": title, "severity": severity,
            "issued": issued, "cves": cves}
