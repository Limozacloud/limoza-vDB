"""Parse AlmaLinux errata (errata.full.json per major) → ALSA advisories.

Each erratum: id (ALSA-…), severity, title, dates, references (cve/rhsa/bugzilla).
No structured CVSS/CWE (Alma points to the CVE page) → advisory + advisory_cve +
cve_vendor (severity) only; per-package fix data = phase 3.
"""
import json
from datetime import datetime, timezone

from ingest.core.cveid import normalize


def parse(raw: bytes):
    return json.loads(raw)


def _ts(v):
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, timezone.utc).isoformat()
    return v or None


def parse_advisory(adv: dict):
    """erratum → (id, title, severity, issued, modified, [cve_ids])."""
    aid = adv.get("id")
    if not aid:
        return None
    cves = [normalize(r.get("id")) for r in (adv.get("references") or [])
            if r.get("type") == "cve"]
    cves = [c for c in cves if c]
    return (aid, adv.get("title"), adv.get("severity"),
            _ts(adv.get("issued_date")), _ts(adv.get("updated_date")), cves)
