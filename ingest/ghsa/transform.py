from typing import Optional

from ingest.purl import ecosystem_purl as _ecosystem_purl


_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "NONE":     "informational",
}

_CVSS_VERSION_MAP = {
    "CVSS_V4": "4.0",
    "CVSS_V3": "3.1",
    "CVSS_V2": "2.0",
}

_REF_TYPE_MAP = {
    "ADVISORY":  "advisory",
    "FIX":       "patch",
    "GIT":       "patch",
    "REPORT":    "report",
    "ARTICLE":   "article",
    "WEB":       "web",
    "PACKAGE":   "web",
    "EVIDENCE":  "web",
    "DETECTION": "web",
}


def _extract_ranges(affected_ranges: list) -> tuple[list, Optional[str], Optional[str]]:
    """Parse OSV ranges into (ranges_list, fix_version, fix_commit).

    Handles ECOSYSTEM, SEMVER, and GIT range types.
    Returns all (introduced, fixed, last_affected) pairs and the latest fix_version.
    """
    ranges = []
    fix_version = None
    fix_commit  = None

    for rng in affected_ranges:
        rng_type = (rng.get("type") or "").upper()
        events   = rng.get("events") or []

        if rng_type == "GIT":
            for e in events:
                if "fixed" in e and not fix_commit:
                    fix_commit = e["fixed"]
            continue

        if rng_type not in ("ECOSYSTEM", "SEMVER"):
            continue

        current_intro: Optional[str] = None
        for e in events:
            if "introduced" in e:
                current_intro = e["introduced"]
            elif "fixed" in e:
                fix_v = e["fixed"]
                ranges.append({
                    "introduced":    current_intro,
                    "fixed":         fix_v,
                    "last_affected": None,
                })
                fix_version   = fix_v
                current_intro = None
            elif "last_affected" in e:
                ranges.append({
                    "introduced":    current_intro,
                    "fixed":         None,
                    "last_affected": e["last_affected"],
                })
                current_intro = None

    return ranges, fix_version, fix_commit


def transform(data: dict) -> list[dict]:
    ghsa_id = data.get("id") or data.get("@id", "")
    if not ghsa_id or data.get("withdrawn"):
        return []

    cve_ids = [
        a for a in (data.get("aliases") or [])
        if isinstance(a, str) and a.startswith("CVE-")
    ]
    if not cve_ids:
        return []

    cve_id  = cve_ids[0]
    aliases = [ghsa_id] + cve_ids

    summary = (data.get("summary") or "").strip()
    details = (data.get("details") or "").strip()

    db_specific  = data.get("database_specific") or {}
    severity_raw = db_specific.get("severity", "")
    cvss_score   = db_specific.get("cvss")

    # CVSS — only insert when a numeric score is available
    cvss = []
    for entry in (data.get("severity") or []):
        stype  = entry.get("type", "")
        vector = entry.get("score", "")
        if not vector or stype not in _CVSS_VERSION_MAP:
            continue
        try:
            score = float(cvss_score)
        except (TypeError, ValueError):
            continue
        cvss.append({
            "version":  _CVSS_VERSION_MAP[stype],
            "score":    score,
            "vector":   vector,
            "severity": _SEVERITY_MAP.get(severity_raw.upper()) if severity_raw else None,
            "source":   "ghsa",
            "advisory": ghsa_id,
        })

    cwes = [
        {"id": c, "name": None, "source": "ghsa", "advisory": ghsa_id}
        for c in (db_specific.get("cwe_ids") or [])
        if isinstance(c, str) and c.startswith("CWE-")
    ]

    refs = [
        {
            "url":     r["url"],
            "type":    _REF_TYPE_MAP.get((r.get("type") or "").upper(), "web"),
            "source":  "ghsa",
            "advisory": ghsa_id,
        }
        for r in (data.get("references") or [])
        if r.get("url")
    ]

    upstream = []
    upstream_by_uid: dict = {}
    for affected in (data.get("affected") or []):
        pkg  = affected.get("package") or {}
        eco  = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        purl = _ecosystem_purl(eco, name)
        if not purl:
            continue

        ranges, fix_version, fix_commit = _extract_ranges(affected.get("ranges") or [])
        versions = affected.get("versions") or None

        uid = f"{ghsa_id}:{eco}:{name}"
        if uid in upstream_by_uid:
            # merge ranges from duplicate entries
            upstream_by_uid[uid]["ranges"] = (upstream_by_uid[uid]["ranges"] or []) + ranges
            if fix_version:
                upstream_by_uid[uid]["fix_version"] = fix_version
            if versions:
                upstream_by_uid[uid]["versions"] = (upstream_by_uid[uid].get("versions") or []) + versions
            continue

        entry = {
            "@id":         uid,
            "purl":        purl,
            "fix_version": fix_version,
            "fix_commit":  fix_commit,
            "ranges":      ranges or None,
            "versions":    versions,
            "source":      "ghsa",
            "advisory":    ghsa_id,
        }
        upstream_by_uid[uid] = entry
        upstream.append(entry)

    published = data.get("published")
    modified  = data.get("modified")

    return [{
        "aliases":      aliases,
        "cve": {
            "cve_id": cve_id,
        },
        "titles":       [{"value": summary, "source": "ghsa", "advisory": ghsa_id}] if summary else [],
        "descriptions": [{"value": details or summary, "source": "ghsa", "advisory": ghsa_id}] if (details or summary) else [],
        "cvss":         cvss,
        "cwes":         cwes,
        "references":   refs,
        "advisories":   [{
            "@id":         ghsa_id,
            "source":      "ghsa",
            "url":         f"https://github.com/advisories/{ghsa_id}",
            "published":   published,
            "updated":     modified,
            "vendor_data": {"github_reviewed": db_specific.get("github_reviewed", False)},
        }],
        "upstream":     upstream,
        "packages":     [],
        "exploits":     [],
        "notices":      [],
        "history":      [],
    }]
