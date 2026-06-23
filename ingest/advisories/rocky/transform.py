"""Parse Rocky Linux advisories from the resf Apollo API (RLSA).

Each advisory carries cves[] with cvss3 vector + base score + cwe → rich:
advisory + advisory_cve + cve_cvss + cve_cwe + cve_vendor (severity).
"""
import json

from ingest.core.cveid import normalize


def parse(raw: bytes):
    return json.loads(raw)


def parse_advisory(adv: dict):
    """apollo advisory → (name, synopsis, severity, published, updated,
                          [(cve, vector, base_score, cwe)])."""
    name = adv.get("name")
    if not name:
        return None
    cves = []
    for c in adv.get("cves") or []:
        cid = normalize(c.get("cve") or "")
        if cid:
            cves.append((cid, c.get("cvss3_scoring_vector"),
                         c.get("cvss3_base_score"), c.get("cwe")))
    return (name, adv.get("synopsis"), adv.get("severity"),
            adv.get("published_at"), adv.get("updated_at"), cves)
