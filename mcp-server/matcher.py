"""Version-compare matcher for the `check_vulnerable` tool.

Self-contained (the MCP server imports nothing from ingest): it queries the tracked
`affected` table via Hasura GraphQL and compares versions with `univers`.
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

_Q_REL = ("query M($eco:String!,$pkg:String!,$rel:String!){"
          " affected(where:{ecosystem:{_eq:$eco},package:{_ilike:$pkg},release:{_eq:$rel}},limit:5000)"
          "{ cve_id source introduced fixed last_affected version_scheme status } }")
_Q_NULL = ("query M($eco:String!,$pkg:String!){"
           " affected(where:{ecosystem:{_eq:$eco},package:{_ilike:$pkg},release:{_is_null:true}},limit:5000)"
           "{ cve_id source introduced fixed last_affected version_scheme status } }")
_Q_CPE = ('query M($cpe:String!){'
          ' affected(where:{coord:{_eq:"cpe"},cpe23:{_eq:$cpe}},limit:5000)'
          '{ cve_id source introduced fixed last_affected version_scheme status } }')


def _v(scheme, s):
    for c in (SCHEME.get(scheme, GenericVersion), GenericVersion):
        try:
            return c(s)
        except Exception:
            continue
    return None


def _vulnerable(scheme, installed, introduced, fixed, last, status):
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
    if last:
        la = _v(scheme, last)
        return (iv <= la) if la is not None else None
    return True


def _parse(purl):
    s = purl[4:] if purl.startswith("pkg:") else purl
    s, _, qs = s.partition("?")
    body, _, version = s.partition("@")
    parts = body.split("/")
    quals = dict(kv.split("=", 1) for kv in qs.split("&") if "=" in kv)
    ptype = parts[0]
    # maven: group:artifact (purl uses "/", GHSA/OSV store ":")
    if ptype in ("rpm", "deb"):
        name = parts[-1]
    elif ptype == "maven":
        name = ":".join(parts[1:])
    else:
        name = "/".join(parts[1:])
    return ptype, name, version or None, quals


def _lane(ptype, version, quals, release):
    if ptype == "rpm":
        if not release:
            m = _DIST.search(version or "")
            release = f"el{m.group(1)}" if m else None
        return "rpm", release
    if ptype == "deb":
        return "deb", release or quals.get("distro")
    return ptype, release


def _parse_cpe(cpe):
    """cpe:2.3:a:openssl:openssl:3.2.4:* → (lookup-key version→*, version field)."""
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
    """Per-CVE cpe verdict. Group by introduced (one range); within a group the host is
    patched once it reaches ANY fix build → parallel fix tracks (Windows security-only vs
    monthly rollup) don't false-positive. Returns the list of contributing rows, or []."""
    groups = {}
    for r in rows:
        if r["status"] not in _SKIP:
            groups.setdefault(r["introduced"], []).append(r)
    hits = []
    for intro, group in groups.items():
        scheme = group[0]["version_scheme"]
        iv = _v(scheme, installed)
        if iv is None:
            continue
        if intro and intro != "0":
            lo = _v(scheme, intro)
            if lo is not None and iv < lo:
                continue
        fixes = [(r, _v(scheme, r["fixed"])) for r in group if r["fixed"]]
        fixes = [(r, fv) for r, fv in fixes if fv is not None]
        lasts = [(r, _v(scheme, r["last_affected"])) for r in group if r["last_affected"]]
        lasts = [(r, lv) for r, lv in lasts if lv is not None]
        if fixes:
            if all(iv < fv for _, fv in fixes):
                rep, _fv = min(fixes, key=lambda x: x[1])
                hits.append(rep)
        elif lasts:
            if any(iv <= lv for _, lv in lasts):
                hits.append(lasts[0][0])
        else:
            hits.append(group[0])
    return hits


async def _check_cpe(hasura, cpe, version):
    key, cv = _parse_cpe(cpe)
    version = version or cv
    if not key:
        raise ValueError("not a cpe 2.3 string")
    if not version:
        raise ValueError("version required")
    data = await hasura.query(_Q_CPE, {"cpe": key})
    by_cve = {}
    for r in data.get("affected") or []:
        by_cve.setdefault(r["cve_id"], []).append(r)
    cves = []
    for cid, rows in sorted(by_cve.items()):
        hits = _cpe_verdict(version, rows)
        if hits:
            cves.append({"cve_id": cid, "status": hits[0]["status"],
                         "fixed_version": hits[0]["fixed"],
                         "sources": sorted({h["source"] for h in hits})})
    return {"ecosystem": "cpe", "release": None, "package": key.split(":")[4], "cves": cves}


async def check(hasura, purl, version, release=None):
    if purl.startswith("cpe:"):
        return await _check_cpe(hasura, purl, version)
    ptype, name, pv, quals = _parse(purl)
    version = version or pv
    if not version:
        raise ValueError("version required")
    eco, rel = _lane(ptype, version, quals, release)
    if rel:
        data = await hasura.query(_Q_REL, {"eco": eco, "pkg": name, "rel": rel})
    else:
        data = await hasura.query(_Q_NULL, {"eco": eco, "pkg": name})
    findings = {}
    for r in data.get("affected") or []:
        if _vulnerable(r["version_scheme"], version, r["introduced"], r["fixed"],
                       r["last_affected"], r["status"]):
            f = findings.setdefault(r["cve_id"], {"cve_id": r["cve_id"], "status": r["status"],
                                                  "fixed_version": r["fixed"], "sources": set()})
            f["sources"].add(r["source"])
    out = sorted(findings.values(), key=lambda x: x["cve_id"])
    for f in out:
        f["sources"] = sorted(f["sources"])
    return {"ecosystem": eco, "release": rel, "package": name, "cves": out}
