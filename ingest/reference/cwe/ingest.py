"""Write CWE weakness definitions into the `cwe` table.

Pattern: pure UPSERT. CWEs are deprecated/obsoleted, never deleted. Rich fields
(consequences, mitigations, …) are stored as JSONB.
"""
import json
from pathlib import Path

from psycopg2.extras import execute_values


def _parse(d: dict) -> dict:
    consequences = [{"scope": c.get("Scope"), "impact": c.get("Impact"), "note": c.get("Note")}
                    for c in (d.get("CommonConsequences") or [])]
    mitigations = [{"phase": m.get("Phase"), "strategy": m.get("Strategy"),
                    "description": m.get("Description"), "effectiveness": m.get("Effectiveness")}
                   for m in (d.get("PotentialMitigations") or [])]
    introductions = [{"phase": m.get("Phase"), "note": m.get("Note")}
                     for m in (d.get("ModesOfIntroduction") or [])]
    detections = [{"method": m.get("Method"), "description": m.get("Description"),
                   "effectiveness": m.get("Effectiveness")}
                  for m in (d.get("DetectionMethods") or [])]
    attack_patterns = [f"CAPEC-{c}" for c in (d.get("RelatedAttackPatterns") or [])]
    related = [{"nature": w.get("Nature"),
                "cwe_id": f"CWE-{w['CweID']}" if w.get("CweID") else None,
                "view_id": w.get("ViewID")}
               for w in (d.get("RelatedWeaknesses") or [])]

    return {
        "cwe_id": f"CWE-{d['ID']}",
        "name": d.get("Name", ""),
        "abstraction": d.get("Abstraction"),
        "description": d.get("Description"),
        "extended_description": d.get("ExtendedDescription"),
        "likelihood_of_exploit": d.get("LikelihoodOfExploit"),
        "common_consequences": consequences or None,
        "potential_mitigations": mitigations or None,
        "modes_of_introduction": introductions or None,
        "detection_methods": detections or None,
        "related_attack_patterns": attack_patterns or None,
        "related_weaknesses": related or None,
    }


def run(conn, dirs: dict) -> int:
    w_path = Path(dirs["cwe"]) / "json_repo" / "W"
    if not w_path.exists():
        print(f"  cwe: {w_path} not found — run `sync cwe` first")
        return 0

    defs = []
    for f in w_path.glob("*.json"):
        try:
            defs.append(_parse(json.loads(f.read_bytes())))
        except Exception:
            pass
    if not defs:
        print("  cwe: no definitions found")
        return 0

    def _j(v):
        return json.dumps(v) if v else None

    rows = [(
        d["cwe_id"], d["name"], d["abstraction"], d["description"], d["extended_description"],
        d["likelihood_of_exploit"], _j(d["common_consequences"]), _j(d["potential_mitigations"]),
        _j(d["modes_of_introduction"]), _j(d["detection_methods"]),
        _j(d["related_attack_patterns"]), _j(d["related_weaknesses"]),
    ) for d in defs]

    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO cwe (cwe_id, name, abstraction, description, extended_description,
                likelihood_of_exploit, common_consequences, potential_mitigations,
                modes_of_introduction, detection_methods, related_attack_patterns,
                related_weaknesses) VALUES %s
            ON CONFLICT (cwe_id) DO UPDATE SET
                name = EXCLUDED.name, abstraction = EXCLUDED.abstraction,
                description = EXCLUDED.description, extended_description = EXCLUDED.extended_description,
                likelihood_of_exploit = EXCLUDED.likelihood_of_exploit,
                common_consequences = EXCLUDED.common_consequences,
                potential_mitigations = EXCLUDED.potential_mitigations,
                modes_of_introduction = EXCLUDED.modes_of_introduction,
                detection_methods = EXCLUDED.detection_methods,
                related_attack_patterns = EXCLUDED.related_attack_patterns,
                related_weaknesses = EXCLUDED.related_weaknesses, synced_at = now()
        """, rows, page_size=2_000)
    conn.commit()
    print(f"  cwe: {len(rows):,} definitions upserted")
    return len(rows)
