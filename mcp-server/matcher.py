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
    name = parts[-1] if ptype in ("rpm", "deb") else "/".join(parts[1:])
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


async def check(hasura, purl, version, release=None):
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
