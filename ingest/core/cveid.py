"""Canonical CVE id normalisation.

With no foreign keys, the cve_id string is the only join key between the spine
and every enrichment table — so it must be byte-identical everywhere. Each source
formats it slightly differently (case, surrounding space, unicode dashes from
copy-pasted advisories), so every importer runs ids through normalize() at the
boundary. Invalid ids return None and are dropped rather than stored as junk.
"""
import re

# Map the various unicode dash/hyphen code points to a plain ASCII hyphen.
_DASHES = str.maketrans({
    "‐": "-", "‑": "-", "‒": "-", "–": "-",
    "—": "-", "―": "-", "−": "-", "­": "-",
})

_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def normalize(value: str) -> str | None:
    """Return the canonical 'CVE-YYYY-NNNN' form, or None if not a valid CVE id."""
    if not value:
        return None
    s = value.strip().upper().translate(_DASHES)
    s = re.sub(r"\s+", "", s)
    return s if _RE.match(s) else None
