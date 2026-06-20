from ingest import json_compat as json

_STATUS_MAP = {
    "Analyzed":            "cve_assigned",
    "Modified":            "cve_assigned",
    "Published":           "cve_assigned",
    "Awaiting Analysis":   "cve_pending",
    "Undergoing Analysis": "cve_pending",
    "Received":            "cve_pending",
    "Deferred":            "cve_pending",
    "Rejected":            "cve_rejected",
    "Reserved":            "cve_reserved",
}

_REF_TYPE_MAP = {
    "Patch":                 "patch",
    "Vendor Advisory":       "advisory",
    "Third Party Advisory":  "advisory",
    "Mitigation":            "advisory",
    "Release Notes":         "article",
    "Mailing List":          "article",
    "Technical Description": "article",
    "Press/Media Coverage":  "article",
    "Issue Tracking":        "report",
    "VDB Entry":             "web",
    "Exploit":               "web",
}

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "NONE":     "informational",
}

_METRIC_KEYS = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2",  "2.0"),
]


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def transform(doc: dict) -> list[dict]:
    cve_id = doc.get("id", "")
    if not cve_id:
        return []

    description = next(
        (d["value"] for d in doc.get("descriptions", []) if d.get("lang") == "en"),
        None,
    )

    cvss = []
    for key, version in _METRIC_KEYS:
        for entry in doc.get("metrics", {}).get(key, []):
            d = entry.get("cvssData", {})
            score = d.get("baseScore")
            if not score:
                continue
            severity_raw = d.get("baseSeverity", "")
            cvss.append({
                "version":  version,
                "score":    score,
                "vector":   d.get("vectorString"),
                "severity": _SEVERITY_MAP.get(severity_raw.upper()),
                "source":   entry.get("source", "nvd@nist.gov"),
                "advisory": None,
            })

    cwes = []
    seen_cwe = set()
    for w in doc.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if d.get("lang") == "en" and val.startswith("CWE-") and val not in seen_cwe:
                seen_cwe.add(val)
                cwes.append({"id": val, "name": None, "source": "nvd", "advisory": None})

    refs = []
    for r in doc.get("references", []):
        url = r.get("url", "")
        if not url:
            continue
        tags = r.get("tags") or []
        ref_type = next((_REF_TYPE_MAP[t] for t in tags if t in _REF_TYPE_MAP), "web")
        refs.append({"url": url, "type": ref_type, "source": "nvd", "advisory": None})

    published    = doc.get("published")
    last_modified = doc.get("lastModified")

    history = []
    if published:
        history.append({
            "date":   published,
            "event":  "advisory_added",
            "source": "nvd",
            "detail": cve_id,
        })
    if last_modified and last_modified != published:
        history.append({
            "date":   last_modified,
            "event":  "advisory_updated",
            "source": "nvd",
            "detail": cve_id,
        })

    return [{
        "aliases":      [cve_id],
        "cve": {
            "cve_id":    cve_id,
            "status":    _STATUS_MAP.get(doc.get("vulnStatus", ""), "cve_pending"),
            "published": published,
            "updated":   last_modified,
        },
        "titles":       [],
        "descriptions": [{"value": description, "source": "nvd", "advisory": None}] if description else [],
        "cvss":         cvss,
        "cwes":         cwes,
        "references":   refs,
        "advisories":   [],
        "upstream":     [],
        "packages":     [],
        "exploits":     [],
        "notices":      [],
        "history":      history,
    }]
