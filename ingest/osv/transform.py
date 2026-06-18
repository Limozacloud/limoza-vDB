"""Transform OSV advisory JSON (package ecosystems) → upsert_lve_record format.

Handles PyPI, npm, Go, crates.io, RubyGems, NuGet, Maven, Packagist, Hex, Pub, Swift,
GitHub Actions. Skips GHSA-prefixed primary IDs (handled by GHSA importer).
"""
from typing import Optional

_CVSS_VERSION_MAP = {
    "CVSS_V4": "4.0",
    "CVSS_V3": "3.1",
    "CVSS_V2": "2.0",
}

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "NONE":     "informational",
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


def _ecosystem_purl(ecosystem: str, name: str, purl_hint: str = "") -> Optional[str]:
    if purl_hint:
        return purl_hint
    if not ecosystem or not name:
        return None
    eco = ecosystem.strip().lower()
    if eco == "npm":
        if name.startswith("@"):
            scope, _, pkg = name[1:].partition("/")
            return f"pkg:npm/%40{scope}/{pkg}" if pkg else None
        return f"pkg:npm/{name}"
    if eco == "pypi":
        return f"pkg:pypi/{name.lower().replace('-', '_')}"
    if eco == "go":
        return f"pkg:golang/{name}"
    if eco == "maven":
        sep = ":" if ":" in name else "/"
        parts = name.split(sep, 1)
        return f"pkg:maven/{parts[0]}/{parts[1]}" if len(parts) == 2 else None
    if eco in ("rubygems", "ruby"):
        return f"pkg:gem/{name}"
    if eco == "nuget":
        return f"pkg:nuget/{name}"
    if eco in ("crates.io", "cargo"):
        return f"pkg:cargo/{name}"
    if eco in ("packagist", "composer"):
        return f"pkg:composer/{name}"
    if eco == "hex":
        return f"pkg:hex/{name}"
    if eco == "pub":
        return f"pkg:pub/{name}"
    if eco == "github actions":
        return f"pkg:githubactions/{name}"
    if eco == "swift":
        return f"pkg:swift/{name}"
    return None


def _extract_ranges(affected_ranges: list) -> tuple[list, Optional[str], Optional[str]]:
    ranges      = []
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
                ranges.append({"introduced": current_intro, "fixed": fix_v, "last_affected": None})
                fix_version   = fix_v
                current_intro = None
            elif "last_affected" in e:
                ranges.append({"introduced": current_intro, "fixed": None, "last_affected": e["last_affected"]})
                current_intro = None

    return ranges, fix_version, fix_commit


def transform(data: dict) -> Optional[dict]:
    osv_id = data.get("id") or ""
    if not osv_id or osv_id.startswith("CVE-") or osv_id.startswith("GHSA-"):
        return None  # CVE-prefixed = raw CVE entry; GHSA = handled by ghsa importer

    if data.get("withdrawn"):
        return None

    aliases = list(data.get("aliases") or [])
    related = list(data.get("related") or [])
    cve_ids = [a for a in aliases + related if isinstance(a, str) and a.startswith("CVE-")]
    if not cve_ids:
        return None

    cve_id     = cve_ids[0]
    all_aliases = [osv_id] + cve_ids

    summary  = (data.get("summary") or "").strip()
    details  = (data.get("details") or "").strip()
    published = data.get("published")
    modified  = data.get("modified")

    db_specific  = data.get("database_specific") or {}
    severity_raw = db_specific.get("severity", "")
    cvss_score   = db_specific.get("cvss")

    # CVSS — only when a numeric score is available
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
            "source":   "osv",
            "advisory": osv_id,
        })

    cwes = [
        {"id": c, "name": None, "source": "osv", "advisory": osv_id}
        for c in (db_specific.get("cwe_ids") or [])
        if isinstance(c, str) and c.startswith("CWE-")
    ]

    refs = [
        {
            "url":      r["url"],
            "type":     _REF_TYPE_MAP.get((r.get("type") or "").upper(), "web"),
            "source":   "osv",
            "advisory": osv_id,
        }
        for r in (data.get("references") or [])
        if r.get("url")
    ]

    upstream      = []
    upstream_by_uid: dict = {}
    for affected in (data.get("affected") or []):
        pkg  = affected.get("package") or {}
        eco  = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        purl = _ecosystem_purl(eco, name, pkg.get("purl", ""))
        if not purl:
            continue

        ranges, fix_version, fix_commit = _extract_ranges(affected.get("ranges") or [])
        versions = affected.get("versions") or None

        uid = f"{osv_id}:{eco}:{name}"
        if uid in upstream_by_uid:
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
            "source":      "osv",
            "advisory":    osv_id,
        }
        upstream_by_uid[uid] = entry
        upstream.append(entry)

    if not upstream:
        return None

    history = []
    if published:
        history.append({"date": published, "event": "advisory_added", "source": "osv", "detail": osv_id})
    if modified and modified != published:
        history.append({"date": modified, "event": "advisory_updated", "source": "osv", "detail": osv_id})

    return {
        "aliases":      all_aliases,
        "cve":          {"cve_id": cve_id},
        "titles":       ([{"value": summary, "source": "osv", "advisory": osv_id}] if summary else []),
        "descriptions": ([{"value": details or summary, "source": "osv", "advisory": osv_id}] if (details or summary) else []),
        "cvss":         cvss,
        "cwes":         cwes,
        "references":   refs,
        "advisories":   [{
            "@id":       osv_id,
            "source":    "osv",
            "url":       f"https://osv.dev/vulnerability/{osv_id}",
            "published": published,
            "updated":   modified,
        }],
        "upstream":     upstream,
        "packages":     [],
        "mitigations":  [],
        "impacts":      [],
        "exploits":     [],
        "notices":      [],
        "history":      history,
    }
