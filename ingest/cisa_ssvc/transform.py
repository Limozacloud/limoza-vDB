from ingest import json_compat as json

# CISA vulnrichment stores values in title-case ("Active", "Yes", "Total")
# our schema expects lowercase ("active", "yes", "total")
_EXPLOITATION_MAP = {
    "none":   "none",
    "poc":    "poc",
    "active": "active",
}

_AUTOMATABLE_MAP = {
    "yes": "yes",
    "no":  "no",
}

_IMPACT_MAP = {
    "partial": "partial",
    "total":   "total",
}


def _norm(value: str, mapping: dict) -> str | None:
    if not value:
        return None
    return mapping.get(value.lower())


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def transform(data: dict) -> list[dict]:
    records = []
    for cve_id, entry in data.items():
        exploitation = _norm(entry.get("ssvc_exploitation", ""), _EXPLOITATION_MAP)
        if not exploitation:
            continue

        records.append({
            "aliases":      [cve_id],
            "has_exploit":  False,
            "cve": {
                "cve_id": cve_id,
                "ssvc": {
                    "exploitation":     exploitation,
                    "automatable":      _norm(entry.get("ssvc_automatable", ""), _AUTOMATABLE_MAP),
                    "technical_impact": _norm(entry.get("ssvc_technical_impact", ""), _IMPACT_MAP),
                },
            },
            "titles":       [],
            "descriptions": [],
            "cvss":         [],
            "cwes":         [],
            "references":   [],
            "advisories":   [],
            "upstream":     [],
            "packages":     [],
            "exploits":     [],
            "notices":      [],
            "history":      [],
        })
    return records
