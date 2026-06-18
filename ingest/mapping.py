import re
import html
import jmespath


# ── Shared transform functions (available to all vendors) ─────────────────────

def strip_html(v, ctx):
    if not v:
        return None
    clean = re.sub(r"<[^>]+>", " ", v)
    return " ".join(html.unescape(clean).split()).strip() or None


_SEVERITY_MAP   = {"Critical": "critical", "Important": "high", "Moderate": "medium", "Low": "low"}
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

def map_severity(values, ctx):
    if not isinstance(values, list):
        values = [values]
    mapped = [_SEVERITY_MAP[x] for x in values if x in _SEVERITY_MAP]
    return max(mapped, key=lambda s: _SEVERITY_ORDER.get(s, 0)) if mapped else None


VEX_JUSTIFICATIONS = frozenset({
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
})

# CSAF remediation category → (affected_state, remediation_state)
CSAF_REM_STATES: dict[str, tuple[str, str]] = {
    "none_available": ("affected", "none"),
    "no_fix_planned": ("affected", "will_not_fix"),
    "fix_deferred":   ("affected", "pending"),
    "workaround":     ("affected", "pending"),
}


def cvss_severity(score) -> str | None:
    """Derive severity label from CVSS v2/v3/v4 numeric score (CVSS standard thresholds)."""
    if score is None:
        return None
    s = float(score)
    if s >= 9.0:  return "critical"
    if s >= 7.0:  return "high"
    if s >= 4.0:  return "medium"
    if s > 0.0:   return "low"
    return "informational"


# ── Engine ────────────────────────────────────────────────────────────────────
#
# MAPPING entry formats:
#   (src, dst)                       simple jmespath → field
#   (src, dst, fn)                   jmespath → fn(value, ctx) → field
#   (src, dst, field_map)            array expansion, no const fields
#   (src, dst, field_map, const)     array expansion with const fields merged in
#
# field_map values can be a jmespath string or a callable(item).

def _expand_array(items, field_map, const):
    result = []
    for item in (items or []):
        entry = dict(const)
        for dst_key, spec in field_map.items():
            entry[dst_key] = spec(item) if callable(spec) else jmespath.search(spec, item)
        result.append(entry)
    return result


def apply_mapping(source, mapping, ctx):
    result = {}
    for entry in mapping:
        src, dst = entry[0], entry[1]
        rest     = entry[2:]

        if not rest:
            result[dst] = jmespath.search(src, source)

        elif len(rest) == 1:
            spec  = rest[0]
            value = jmespath.search(src, source)
            if callable(spec):
                result[dst] = spec(value, ctx)
            else:
                result[dst] = _expand_array(value, spec, {})

        else:
            field_map, const = rest[0], rest[1]
            result[dst] = _expand_array(jmespath.search(src, source), field_map, const)

    return result
