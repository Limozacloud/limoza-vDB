"""Parse a GHSA OSV record (github-reviewed) → advisory + per-CVE enrichment.

GHSA = the ecosystem-world equivalent of cvelistv5: it carries the upstream
advisory (L2), the ecosystem package identities (L3, purls) and version ranges
(L4) for packages that have no dedicated CNA. We are CVE-centric, so records
without a CVE alias are skipped (nothing to hang them on).
"""
import json

from ingest.core.cveid import normalize
from ingest.core.cvss import score_from_vector, severity_from_score


# OSV ecosystem → purl type (raw GHSA files carry {ecosystem,name}, not purl)
_PURL_TYPE = {
    "PyPI": "pypi", "npm": "npm", "Maven": "maven", "Go": "golang",
    "RubyGems": "gem", "crates.io": "cargo", "NuGet": "nuget",
    "Packagist": "composer", "Pub": "pub", "Hex": "hex", "Hackage": "hackage",
    "SwiftURL": "swift", "Bitnami": "bitnami", "GitHub Actions": "github",
}


def _purl(pkg: dict):
    if pkg.get("purl"):
        return pkg["purl"]
    eco, name = pkg.get("ecosystem"), pkg.get("name")
    if not (eco and name):
        return None
    return f"pkg:{_PURL_TYPE.get(eco, eco.lower())}/{name.lower() if eco == 'PyPI' else name}"


def parse(raw: bytes):
    return json.loads(raw)


def transform(d: dict, source):
    gid = d.get("id")
    if not gid or not gid.startswith("GHSA"):
        return None
    cves = [c for c in (normalize(a) for a in (d.get("aliases") or [])) if c]
    if not cves:
        return None   # CVE-centric → skip GHSA-only advisories

    ds = d.get("database_specific") or {}

    cvss = []
    for s in d.get("severity") or []:
        vec = s.get("score")
        if not (vec and vec.startswith("CVSS")):
            continue
        ver, sc = score_from_vector(vec)        # (None, None) for v2/v4 → skip
        if ver:
            cvss.append((source, ver, sc, severity_from_score(sc, ver), vec))

    cwe = [(source, c) for c in (ds.get("cwe_ids") or []) if str(c).startswith("CWE-")]

    packages = []
    for a in d.get("affected") or []:
        purl = _purl(a.get("package") or {})
        if not purl:
            continue
        spans = []
        for r in a.get("ranges") or []:
            ev = []
            for e in r.get("events") or []:
                if e.get("introduced") and e["introduced"] != "0":
                    ev.append(">=" + e["introduced"])
                if e.get("fixed"):
                    ev.append("<" + e["fixed"])
                if e.get("last_affected"):
                    ev.append("<=" + e["last_affected"])
            if ev:
                spans.append(" ".join(ev))
        packages.append({"purl": purl, "ranges": "; ".join(spans) or None})

    return {
        "id": gid,
        "cves": cves,
        "title": d.get("summary"),
        "details": (d.get("details") or "").strip() or None,  # full description (markdown)
        "severity": ds.get("severity"),                       # CRITICAL/HIGH/MODERATE/LOW
        "published": d.get("published"),
        "modified": d.get("modified"),
        "url": f"https://github.com/advisories/{gid}",
        "cvss": cvss,
        "cwe": cwe,
        "packages": packages,
    }
