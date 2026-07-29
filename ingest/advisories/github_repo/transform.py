"""Parse a per-repository GitHub Security Advisory (REST API shape) → normalised dict.

CVE-centric: advisories without a CVE id are skipped (nothing to hang them on). Only
`state=published`, non-withdrawn advisories are kept. Affected versions come from
`vulnerabilities[]` (`vulnerable_version_range` + `patched_versions`); for non-ecosystem
software these have no package name, so we key the affected row on a synthetic
`pkg:github/{owner}/{repo}` purl with the `generic` version scheme.
"""
import re

from ingest.core.cveid import normalize
from ingest.core.cvss import score_from_vector, severity_from_score

# OSV/GitHub ecosystem label → purl type; unknown/empty → the synthetic github repo purl.
_PURL_TYPE = {
    "pip": "pypi", "npm": "npm", "maven": "maven", "go": "golang", "rubygems": "gem",
    "cargo": "cargo", "nuget": "nuget", "composer": "composer", "pub": "pub",
    "erlang": "hex", "swift": "swift",
}


def _clean_ver(v: str) -> str:
    return (v or "").strip().lstrip("vV").strip()


_CONSTRAINT = re.compile(r"\s*(>=|<=|>|<|=)?\s*v?([0-9][\w.+-]*)")


def _ranges(vuln_range: str | None, patched: str | None) -> str | None:
    """GitHub range (`>= 1.0, < 2.0` / `<= v8.9.6.4`) + `patched_versions` → the
    `>=x <y` span string the affected extractor parses. Operators and versions are
    space-separated in GitHub's format. A fix (`patched_versions`) is the upper `<` bound."""
    intro = fixed = last = None
    for part in (vuln_range or "").split(","):
        m = _CONSTRAINT.match(part.strip())
        if not m or not m.group(2):
            continue
        op, ver = (m.group(1) or "="), _clean_ver(m.group(2))
        if op in (">=", ">"):
            intro = ver
        elif op == "<":
            fixed = ver
        else:                      # <= or exact = → upper-inclusive bound
            last = ver
    if patched:
        fixed = _clean_ver(patched.split(",")[0]) or fixed
    parts = []
    if intro:
        parts.append(f">={intro}")
    if fixed:
        parts.append(f"<{fixed}")
    elif last:
        parts.append(f"<={last}")
    return " ".join(parts) or None


def transform(a: dict, repo: str):
    if a.get("state") != "published" or a.get("withdrawn_at"):
        return None
    cid = normalize(a.get("cve_id") or "")
    if not cid:                          # CVE-centric — repo advisories without a CVE are dropped
        return None

    cvss = []
    vec = ((a.get("cvss") or {}).get("vector_string")) or ""
    if vec.startswith("CVSS"):
        ver, sc = score_from_vector(vec)              # v2/v4 → (None, None)
        if ver is None:                               # keep the advisory's own score if given
            m = re.match(r"CVSS:(\d+\.\d+)", vec)
            ver, sc = (m.group(1) if m else None), (a.get("cvss") or {}).get("score")
        if ver:
            cvss.append((ver, sc, severity_from_score(sc, ver) if sc is not None else None, vec))

    cwes = [c["cwe_id"] for c in (a.get("cwes") or []) if str(c.get("cwe_id", "")).startswith("CWE-")]

    packages = []
    for v in a.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        eco = (pkg.get("ecosystem") or "").strip()
        name = (pkg.get("name") or "").strip()
        rng = _ranges(v.get("vulnerable_version_range"), v.get("patched_versions"))
        if eco and name:                              # real ecosystem package (rare on repo advisories)
            purl = f"pkg:{_PURL_TYPE.get(eco.lower(), eco.lower())}/{name}"
        else:                                         # non-ecosystem app → key on the repo itself
            purl = f"pkg:github/{repo}"
        packages.append({"purl": purl, "ranges": rng})
    if not packages:                                  # still record the repo as the affected coord
        packages.append({"purl": f"pkg:github/{repo}", "ranges": None})

    return {
        "id":        a.get("ghsa_id"),
        "cve":       cid,
        "url":       a.get("html_url"),
        "title":     a.get("summary"),
        "details":   a.get("description"),
        "severity":  a.get("severity"),
        "published": a.get("published_at"),
        "modified":  a.get("updated_at"),
        "cvss":      cvss,
        "cwe":       cwes,
        "refs":      [r.get("url") for r in (a.get("references") or []) if r.get("url")],
        "packages":  packages,
    }
