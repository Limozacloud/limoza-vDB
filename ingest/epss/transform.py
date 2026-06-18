import json


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def transform(data: dict) -> list[dict]:
    records = []
    for cve_id, vals in data.items():
        if len(vals) < 2:
            continue
        records.append({
            "aliases":      [cve_id],
            "has_exploit":  False,
            "cve": {
                "cve_id": cve_id,
                "epss": {
                    "score":      float(vals[0]),
                    "percentile": float(vals[1]),
                    "date":       vals[2] if len(vals) > 2 else None,
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
