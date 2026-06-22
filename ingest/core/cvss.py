"""CVSS helpers shared across importers."""


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
