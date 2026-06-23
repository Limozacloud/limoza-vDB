"""The canonical affected-status enum + per-source normalization.

Every source's native vocabulary is mapped onto these six values; the matcher and
the API only ever see these. The source's original string is kept separately in
``affected.status_raw``.
"""

# ── the six canonical states (drive the matcher) ──────────────────────────────
NOT_AFFECTED        = "not_affected"         # explicitly not affected  → suppress
UNDER_INVESTIGATION = "under_investigation"  # being assessed           → don't flag
AFFECTED            = "affected"             # vulnerable, no fix yet    → flag
FIXED               = "fixed"                # fixed in a version        → flag if installed < fixed
WONT_FIX            = "wont_fix"             # vulnerable, no fix coming → flag (labelled)
UNKNOWN             = "unknown"              # no statement              → grey zone

# ── version-compare scheme per ecosystem ──────────────────────────────────────
_SCHEME = {
    "rpm": "rpm", "deb": "deb", "apk": "apk",
    "pypi": "pep440", "npm": "semver", "golang": "semver", "cargo": "semver",
    "composer": "semver", "gem": "gem", "maven": "maven", "nuget": "nuget", "hex": "semver",
}


def scheme(ecosystem: str | None) -> str:
    return _SCHEME.get((ecosystem or "").lower(), "generic")


# ── CSAF VEX (Red Hat / SUSE) ─────────────────────────────────────────────────
# flag label → human justification (the "why" behind a not_affected)
CSAF_JUSTIFICATION = {
    "component_not_present":                             "component not present",
    "vulnerable_code_not_present":                       "vulnerable code not present",
    "vulnerable_code_not_in_execute_path":              "not in execute path",
    "vulnerable_code_cannot_be_controlled_by_adversary": "not adversary-controllable",
    "inline_mitigations_already_exist":                  "inline mitigations exist",
}


def from_csaf_remediation(category: str | None, details: str | None) -> str:
    """CSAF remediation category (+ vendor detail string) → canonical status."""
    d = (details or "").lower()
    if category == "vendor_fix":
        return FIXED
    if category == "no_fix_planned":
        return WONT_FIX                       # incl. "out of support scope"
    # none_available / workaround / mitigation / unknown → still vulnerable now
    return AFFECTED                           # "fix deferred" is affected-now
