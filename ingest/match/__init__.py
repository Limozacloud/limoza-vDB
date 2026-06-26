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
    # `generic` is the unmanaged / CPE lane (Microsoft & SQL builds, NVD CPE configs, bundled
    # binaries, LVE). MavenVersion is its comparator: it tokenises numeric + alphanumeric, so
    # numeric parts rank numerically (17.9 < 17.10, UBR .9 < .10) AND letter versions work
    # (openssl 1.1.1w < 1.1.1x) — without the lexical breakage of univers' GenericVersion.
    "composer": ComposerVersion, "generic": MavenVersion,
}
# wont_fix is excluded from the vulnerable verdict (Debian no-dsa "ignored", urgency
# "unimportant"/"end-of-life", …): the finding stays in the DB with its justification so it's
# auditable via GraphQL, but it doesn't count as an actionable vulnerability in /match.
_SKIP = {"not_affected", "under_investigation", "unknown", "wont_fix"}
_DIST = re.compile(r"\.el(\d+(?:_\d+)?)")

# scanners emit the purl distro as ID-VERSION_ID (debian-11, ubuntu-22.04); the Debian/Ubuntu
# trackers — and so our affected rows — are keyed by codename. Map to codename; pass through
# values that are already a codename.
_DISTRO_CODENAME = {
    "debian-7": "wheezy", "debian-8": "jessie", "debian-9": "stretch",
    "debian-10": "buster", "debian-11": "bullseye", "debian-12": "bookworm",
    "debian-13": "trixie", "debian-14": "forky", "debian-sid": "sid",
    "ubuntu-14.04": "trusty", "ubuntu-16.04": "xenial", "ubuntu-18.04": "bionic",
    "ubuntu-20.04": "focal", "ubuntu-22.04": "jammy", "ubuntu-22.10": "kinetic",
    "ubuntu-23.04": "lunar", "ubuntu-23.10": "mantic", "ubuntu-24.04": "noble",
    "ubuntu-24.10": "oracular", "ubuntu-25.04": "plucky",
}


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
        # Debian/RPM advisories are keyed by SOURCE package; scanners put the binary in the
        # purl name and the source in the `upstream` qualifier (zlib1g-dev → upstream=zlib).
        name = quals.get("upstream") or parts[-1]
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
        rel = release or quals.get("distro")
        return "deb", _DISTRO_CODENAME.get(rel, rel)     # debian-11 → bullseye
    return ptype, release          # ecosystem package — release stays None


def parse_cpe(cpe):
    """cpe:2.3:a:openssl:openssl:3.2.4:* → (lookup-key, version).

    key = cpe:2.3:<part>:<vendor>:<product>:*:*:… (matches affected.cpe23, version→*);
    version = the cpe version field (the installed build / version).
    """
    raw = cpe.lower().split(":")
    if len(raw) < 6 or raw[0] != "cpe":
        return None, None
    p = (raw + ["*"] * 13)[:13]
    ver = p[5] if p[5] not in ("*", "-", "") else None
    upd = p[6] if p[6] not in ("-", "") else "*"      # keep update (e.g. r2); -/"" → *
    # key mirrors cpe_norm._key: cpe:2.3:part:vendor:product:*:update:*…  (13 fields)
    key = ":".join(["cpe", "2.3", p[2], p[3], p[4], "*", upd] + ["*"] * 6)
    return key, ver


def _cpe_verdict(installed, rows):
    """rows for one CVE: list of (src, introduced, fixed, last_affected, scheme, status).

    Group by ``introduced`` (= one affected range). Within a group the host counts as
    patched as soon as it reaches ANY of the group's fix builds — so parallel fix tracks
    (Windows security-only vs monthly rollup, with different build numbers) don't
    false-positive. Distinct ranges (different ``introduced``) are OR'd as usual.
    Returns [(src, status, fixed), …] or [] when not vulnerable.
    """
    groups = {}
    for r in rows:
        if r[5] not in _SKIP:
            groups.setdefault(r[1], []).append(r)        # by introduced
    hits = []
    for intro, group in groups.items():
        scheme = group[0][4]
        iv = _v(scheme, installed)
        if iv is None:
            continue
        if intro and intro != "0":
            lo = _v(scheme, intro)
            if lo is not None and iv < lo:
                continue                                  # below this range
        had_bounds = any(r[2] or r[3] for r in group)     # rows that specify a fixed / last bound
        fixes = [(r, _v(scheme, r[2])) for r in group if r[2]]
        fixes = [(r, fv) for r, fv in fixes if fv is not None]
        lasts = [(r, _v(scheme, r[3])) for r in group if r[3]]
        lasts = [(r, lv) for r, lv in lasts if lv is not None]
        if fixes:
            if all(iv < fv for _, fv in fixes):           # not reached by any fix track
                rep, _fv = min(fixes, key=lambda x: x[1])
                hits.append((rep[0], rep[5], rep[2]))
        elif lasts:
            if any(iv <= lv for _, lv in lasts):
                hits.append((lasts[0][0][0], lasts[0][0][5], None))
        elif had_bounds:
            continue                                       # had a fixed/last bound but it didn't
            #                                                parse → can't decide → don't flag (no FP)
        else:
            hits.append((group[0][0], group[0][5], None))  # genuinely no bound → open-ended affected
    return hits


def match_cpe(conn, cpe, version=None):
    """Match a CPE 2.3 string (from a binary/registry cataloger) against the cpe lane."""
    key, cv = parse_cpe(cpe)
    version = version or cv
    if not key:
        raise ValueError("not a cpe 2.3 string")
    if not version:
        raise ValueError("no version (give cpe:…:<version>:… or a second arg)")
    sql = ("SELECT cve_id, source, introduced, fixed, last_affected, version_scheme, status "
           "FROM affected WHERE coord = 'cpe' AND cpe23 = %s")
    by_cve = {}
    with conn.cursor() as cur:
        cur.execute(sql, (key,))
        for cid, src, intro, fixed, last, scheme, status in cur.fetchall():
            by_cve.setdefault(cid, []).append((src, intro, fixed, last, scheme, status))
    return {cid: hits for cid, rows in by_cve.items() if (hits := _cpe_verdict(version, rows))}


def match(conn, purl, version=None, release=None):
    """Return {cve_id: [(source, status, fixed), …]} for the vulnerable hits."""
    if purl.startswith("cpe:"):
        return match_cpe(conn, purl, version)
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
