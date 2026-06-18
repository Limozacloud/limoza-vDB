"""CWE dictionary lookup from local json_repo/W/ clone.

Builds an in-memory map CWE-id -> full weakness definition from
``json_repo/W/*.json``. Two consumers:

* ``lookup(cwe_id, dirs)``        -> weakness name only (fallback for lve_cwes.name)
* ``lookup_detail(cwe_id, dirs)`` -> full definition dict for the ``cwe`` table
"""
import json
from pathlib import Path

_cache: dict[str, dict] | None = None


def _parse(d: dict) -> dict:
    """Map a raw json_repo/W weakness object to ``cwe`` table column shape."""
    cwe_id = f"CWE-{d['ID']}"

    consequences = [
        {"scope": c.get("Scope"), "impact": c.get("Impact"), "note": c.get("Note")}
        for c in (d.get("CommonConsequences") or [])
    ]
    mitigations = [
        {
            "phase": m.get("Phase"),
            "strategy": m.get("Strategy"),
            "description": m.get("Description"),
            "effectiveness": m.get("Effectiveness"),
        }
        for m in (d.get("PotentialMitigations") or [])
    ]
    introductions = [
        {"phase": m.get("Phase"), "note": m.get("Note")}
        for m in (d.get("ModesOfIntroduction") or [])
    ]
    detections = [
        {
            "method": m.get("Method"),
            "description": m.get("Description"),
            "effectiveness": m.get("Effectiveness"),
        }
        for m in (d.get("DetectionMethods") or [])
    ]
    attack_patterns = [f"CAPEC-{c}" for c in (d.get("RelatedAttackPatterns") or [])]
    related = [
        {
            "nature": w.get("Nature"),
            "cwe_id": f"CWE-{w['CweID']}" if w.get("CweID") else None,
            "view_id": w.get("ViewID"),
        }
        for w in (d.get("RelatedWeaknesses") or [])
    ]

    return {
        "cwe_id": cwe_id,
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


def _load(dirs: dict) -> dict[str, dict]:
    global _cache
    if _cache is not None:
        return _cache
    w_path = Path(dirs["cwe_db"]) / "json_repo" / "W"
    if not w_path.exists():
        _cache = {}
        return _cache
    index = {}
    for f in w_path.glob("*.json"):
        try:
            detail = _parse(json.loads(f.read_bytes()))
            index[detail["cwe_id"]] = detail
        except Exception:
            pass
    _cache = index
    return _cache


def lookup(cwe_id: str, dirs: dict) -> str | None:
    """Return CWE name for 'CWE-NNN', or None if not found."""
    detail = _load(dirs).get(cwe_id)
    return detail["name"] if detail else None


def lookup_detail(cwe_id: str, dirs: dict) -> dict | None:
    """Return the full CWE definition dict for 'CWE-NNN', or None if not found."""
    return _load(dirs).get(cwe_id)
