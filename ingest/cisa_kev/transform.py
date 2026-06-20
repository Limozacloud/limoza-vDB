from ingest import json_compat as json


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def transform(data: dict) -> list[dict]:
    records = []
    for cve_id, entry in data.items():
        known_ransomware = entry.get("known_ransomware")
        if isinstance(known_ransomware, str):
            # CISA emits "Known" / "Unknown" — only "Known" means a confirmed campaign.
            known_ransomware = known_ransomware.strip().lower() == "known"

        records.append({
            "aliases":      [cve_id],
            "has_exploit":  False,
            "cve": {
                "cve_id": cve_id,
                "kev": {
                    "date_added":       entry.get("date_added") or None,
                    "due_date":         entry.get("due_date") or None,
                    "known_ransomware": known_ransomware,
                    "required_action":  entry.get("required_action") or None,
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
