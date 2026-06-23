"""OSV native-ecosystem record → advisory + advisory_cve (L3 ecosystem advisory).

Only native DBs are kept (id-prefix → source); GHSA/MAL/CVE/GSD/OSV are dropped.
"""
import json

from ingest.core.cveid import normalize

# native advisory DB prefix → our source name (the issuer)
_SOURCE = {"PYSEC": "pypa", "GO": "go", "RUSTSEC": "rustsec", "EEF": "eef", "DRUPAL": "drupal"}

# OSV ecosystem → purl type (for package-match disambiguation of loose multi-CVE aliases)
_PURL_TYPE = {
    "PyPI": "pypi", "npm": "npm", "Maven": "maven", "Go": "golang",
    "RubyGems": "gem", "crates.io": "cargo", "NuGet": "nuget",
    "Packagist": "composer", "Pub": "pub", "Hex": "hex", "Hackage": "hackage",
}


def parse(raw: bytes):
    return json.loads(raw)


def _purl(pkg: dict):
    if pkg.get("purl"):
        return pkg["purl"].split("@")[0]
    eco, name = pkg.get("ecosystem"), pkg.get("name")
    if not (eco and name):
        return None
    return f"pkg:{_PURL_TYPE.get(eco, eco.lower())}/{name.lower() if eco == 'PyPI' else name}"


def _url(prefix, pid, d):
    if prefix == "GO":
        return f"https://pkg.go.dev/vuln/{pid}"
    if prefix == "RUSTSEC":
        return f"https://rustsec.org/advisories/{pid}.html"
    for a in d.get("affected") or []:
        s = (a.get("database_specific") or {}).get("source")
        if s:
            return s
    return (d.get("database_specific") or {}).get("source") or f"https://osv.dev/vulnerability/{pid}"


def transform(d: dict):
    pid = d.get("id")
    if not pid:
        return None
    src = _SOURCE.get(pid.split("-")[0])
    if not src or d.get("withdrawn"):
        return None                       # only native DBs, skip withdrawn
    cves = [c for c in (normalize(a) for a in (d.get("aliases") or [])) if c]
    if not cves:
        return None                       # CVE-centric
    title = d.get("summary") or (d.get("details") or "")[:100].strip() or None
    packages = []
    for af in d.get("affected") or []:
        purl = _purl(af.get("package") or {})
        if not purl:
            continue
        spans = []
        for r in af.get("ranges") or []:
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
    purls = {p["purl"] for p in packages}
    return {"id": pid, "source": src, "cves": cves, "title": title,
            "details": (d.get("details") or "").strip() or None,
            "url": _url(pid.split("-")[0], pid, d), "packages": packages, "purls": purls,
            "published": d.get("published"), "modified": d.get("modified")}
