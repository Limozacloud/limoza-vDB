"""The matcher — hold a scanned component against the affected table.

Shared core behind both the CLI (`vdb match`), the future /match HTTP endpoint, and
the MCP `check_vulnerable` tool. Version comparison uses `univers` (per-ecosystem
version classes); the canonical status decides the verdict.

A component is a purl (glance's output) with a version, optionally a release:
    pkg:rpm/redhat/openssl@1.0.1e-30.el6_6.1     → rpm, release from the dist tag
    pkg:deb/ubuntu/curl@7.81.0-1?distro=jammy    → deb, release=jammy
    pkg:pypi/django@2.0                          → ecosystem pypi, no release
"""
import re

from univers.versions import (AlpineLinuxVersion, ComposerVersion, DebianVersion,
                               GenericVersion, GolangVersion, MavenVersion, NugetVersion,
                               PypiVersion, RpmVersion, RubygemsVersion, SemverVersion)

SCHEME = {
    "rpm": RpmVersion, "deb": DebianVersion, "apk": AlpineLinuxVersion,
    "semver": SemverVersion, "pep440": PypiVersion, "maven": MavenVersion,
    "golang": GolangVersion, "gem": RubygemsVersion, "nuget": NugetVersion,
    "composer": ComposerVersion, "generic": GenericVersion,
}
_SKIP = {"not_affected", "under_investigation", "unknown"}
_DIST = re.compile(r"\.el(\d+(?:_\d+)?)")


def _v(scheme, s):
    cls = SCHEME.get(scheme, GenericVersion)
    for c in (cls, GenericVersion):
        try:
            return c(s)
        except Exception:
            continue
    return None


def is_vulnerable(scheme, installed, introduced, fixed, last_affected, status):
    """True/False, or None when the versions can't be compared."""
    if status in _SKIP:
        return False
    iv = _v(scheme, installed)
    if iv is None:
        return None
    if introduced and introduced != "0":
        lo = _v(scheme, introduced)
        if lo is not None and iv < lo:
            return False
    if fixed:
        fx = _v(scheme, fixed)
        return (iv < fx) if fx is not None else None
    if last_affected:
        la = _v(scheme, last_affected)
        return (iv <= la) if la is not None else None
    return True                                   # affected/wont_fix, no upper bound


def parse_purl(purl):
    s = purl[4:] if purl.startswith("pkg:") else purl
    s, _, qs = s.partition("?")
    body, _, version = s.partition("@")
    parts = body.split("/")
    quals = dict(kv.split("=", 1) for kv in qs.split("&") if "=" in kv)
    ptype = parts[0]
    # rpm/deb: bare package name (namespace=redhat/ubuntu dropped, like affected.package);
    # maven: group:artifact (purl uses "/", but GHSA/OSV store the ":" form);
    # other ecosystems: name as-is (django, @scope/x, …)
    if ptype in ("rpm", "deb"):
        name = parts[-1]
    elif ptype == "maven":
        name = ":".join(parts[1:])
    else:
        name = "/".join(parts[1:])
    return ptype, name, version or None, quals


def _lane(ptype, version, quals, release=None):
    """→ (ecosystem, release) for the affected lookup."""
    if ptype == "rpm":
        if not release:
            m = _DIST.search(version or "")
            release = f"el{m.group(1)}" if m else None
        return "rpm", release
    if ptype == "deb":
        return "deb", release or quals.get("distro")
    return ptype, release          # ecosystem package — release stays None


def match(conn, purl, version=None, release=None):
    """Return {cve_id: [(source, status, fixed), …]} for the vulnerable hits."""
    ptype, name, pv, quals = parse_purl(purl)
    version = version or pv
    if not version:
        raise ValueError("no version (give pkg@version or a second arg)")
    eco, rel = _lane(ptype, version, quals, release)
    sql = ("SELECT cve_id, source, release, introduced, fixed, last_affected, "
           "version_scheme, status FROM affected "
           "WHERE ecosystem = %s AND lower(package) = lower(%s) "
           "AND (release = %s OR (%s::text IS NULL AND release IS NULL))")
    findings = {}
    with conn.cursor() as cur:
        cur.execute(sql, (eco, name, rel, rel))
        for cid, src, _r, intro, fixed, last, scheme, status in cur.fetchall():
            if is_vulnerable(scheme, version, intro, fixed, last, status):
                findings.setdefault(cid, []).append((src, status, fixed))
    return findings
