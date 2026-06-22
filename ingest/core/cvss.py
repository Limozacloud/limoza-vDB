"""CVSS helpers shared across importers."""
import math

_AV   = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC   = {"L": 0.77, "H": 0.44}
_UI   = {"N": 0.85, "R": 0.62}
_CIA  = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # scope changed


def _roundup(x):
    """CVSS 3.1 roundup — to the nearest 0.1, always up on ties above."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def score_from_vector(vector):
    """CVSS v3.0/3.1 base score from a vector string → (version, score) or (None, None).

    Sources like Ubuntu's OSV give the vector but no base score; we compute it
    with the official formula so cve_cvss gets a real score + severity.
    """
    if not vector or not vector.startswith("CVSS:3"):
        return (None, None)                      # only v3.x here (v2/v4 → caller skips)
    parts = vector.split("/")
    ver = parts[0].split(":", 1)[1]
    m = dict(p.split(":", 1) for p in parts[1:] if ":" in p)
    try:
        changed = m["S"] == "C"
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_C if changed else _PR_U)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return (None, None)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = (7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)) if changed else 6.42 * iss
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return (ver, 0.0)
    raw = 1.08 * (impact + expl) if changed else (impact + expl)
    return (ver, _roundup(min(raw, 10)))


def severity_from_score(base_score, version):
    """Qualitative severity bucket from a CVSS base score.

    CVSS v2 has no severity field in the standard (buckets came with v3), so we
    derive it. v2 and v3/v4 use different thresholds.
    """
    if base_score is None:
        return None
    s = float(base_score)
    if (version or "").startswith("2"):                 # CVSS v2
        if s >= 7.0:
            return "high"
        if s >= 4.0:
            return "medium"
        return "low"
    # CVSS v3 / v4
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s >= 0.1:
        return "low"
    return "none"
