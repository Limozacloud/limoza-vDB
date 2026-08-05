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
from urllib.parse import unquote

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
# Raw vendor fix-states that are deprioritised the same way wont_fix is: the row stays in the DB
# (canonical status = affected, auditable via GraphQL) but is NOT flagged in /match. Red Hat's
# "Fix deferred" means the fix is postponed indefinitely — treated like Debian no-dsa / Ubuntu
# "deferred", which already map to wont_fix. Matched against affected.status_raw (Red Hat/clones).
_SKIP_RAW = {"Fix deferred"}
_DIST = re.compile(r"\.el(\d+(?:_\d+)?)")

# Ubuntu's "-signed" kernel packages (secure-boot signature wrapper around a flavor's real
# build, e.g. linux-image-*-gcp → upstream=linux-signed-gcp-6.17) are never tracked as their
# own entity in Ubuntu's security data — only the base flavor build is (linux-gcp, linux-hwe,
# generic → plain "linux"). Strip "signed-" and any trailing HWE version tag before lookup.
_UBUNTU_SIGNED = re.compile(r"^linux-signed(?:-([a-z]+))?")

# ── curation: human overrides applied at match time (see the `curation` table) ────────────
# A rule targets a CVE and, via its non-NULL selector fields, a subset of that CVE's affected
# rows: suppress drops them, set_status forces a status, set_fixed corrects a bound. Loaded once
# per match() call (or passed in for a bulk run) and applied after the affected rows are fetched.
_CUR_SEL = ("coord", "ecosystem", "package", "cpe23", "release", "source")


def load_curations(conn) -> dict:
    """Active curation rules → {cve_id: [rule dict, …]} (expired rules excluded)."""
    cols = ("cve_id", "action", *_CUR_SEL, "status", "fixed", "introduced", "last_affected")
    out = {}
    with conn.cursor() as cur:
        cur.execute(f"SELECT {','.join(cols)} FROM curation "
                    "WHERE expires_at IS NULL OR expires_at > now()")
        for r in cur.fetchall():
            d = dict(zip(cols, r))
            out.setdefault(d["cve_id"], []).append(d)
    return out


def _curate(cid, ctx, curations):
    """Apply matching curation rules to one affected row's context (dict with the selector +
    status/fixed/introduced/last_affected). Returns the (possibly mutated) ctx, or None to
    suppress. Selector: a non-NULL rule field must equal the row's value (case-insensitive)."""
    for c in curations.get(cid, ()):  # ()=no rules for this cve
        if any(c[k] is not None and (ctx.get(k) or "").lower() != c[k].lower() for k in _CUR_SEL):
            continue                                              # selector doesn't match this row
        if c["action"] == "suppress":
            return None
        if c["action"] == "set_status":
            ctx["status"] = c["status"]
        elif c["action"] == "set_fixed":
            for f in ("fixed", "introduced", "last_affected"):
                if c[f] is not None:
                    ctx[f] = c[f]
    return ctx

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
    # Parse with the scheme's OWN class only — no GenericVersion cross-fallback. The fallback let a
    # non-version value (e.g. an OSV "GIT" commit hash stored in `fixed`) parse as GenericVersion,
    # which then crashed the compare (PypiVersion < GenericVersion → TypeError → whole component
    # "unknown"). Unparseable in the scheme → None → that bound is skipped, not mixed.
    try:
        return SCHEME.get(scheme, GenericVersion)(s)
    except Exception:
        return None


def _strip_epoch(v: str) -> str:
    """Drop a leading `N:` epoch so a version compares on version-release alone (rpm/deb)."""
    return v.split(":", 1)[1] if ":" in v else v


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
        if fx is None:
            return None
        if not (iv < fx):
            return False
        # no-downgrade guard (rpm/deb): a fix is a real upgrade only when the host is below it in
        # version-release too, not solely by epoch. A higher-epoch but OLDER build — e.g. Oracle's
        # malformed 31:qemu-7.2.0-37 against a 17:qemu-9.1.0 host — would otherwise flag the host
        # and be surfaced as a "fix" that is actually a downgrade. Legit epoch bumps (higher epoch
        # AND version) still pass, since there the host is genuinely below in version-release too.
        if scheme in ("rpm", "deb"):
            hv, fv = _v(scheme, _strip_epoch(installed)), _v(scheme, _strip_epoch(fixed))
            if hv is not None and fv is not None and hv >= fv:
                return False
        return True
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
    namespace = parts[1] if len(parts) > 2 else None   # rpm/deb vendor (redhat/oracle/ubuntu/…)
    # rpm/deb: bare package name (namespace kept separately — it is the vendor, e.g. redhat);
    # maven: group:artifact (purl uses "/", but GHSA/OSV store the ":" form);
    # other ecosystems: name as-is (django, @scope/x, …)
    if ptype in ("rpm", "deb"):
        # Debian/RPM advisories are keyed by SOURCE package; scanners put the binary in the
        # purl name and the source in the `upstream` qualifier (zlib1g-dev → upstream=zlib).
        name = quals.get("upstream") or parts[-1]
        if ptype == "deb":
            m = _UBUNTU_SIGNED.match(name)
            if m:
                name = f"linux-{m.group(1)}" if m.group(1) else "linux"
    elif ptype == "maven":
        name = ":".join(parts[1:])
    else:
        name = "/".join(parts[1:])
    return ptype, name, version or None, quals, namespace


_EL_TAG = re.compile(r"^el(\d+)(?:_(\d+))?$", re.I)
# scanners label RHEL-family distros as <name>-<major>[.<minor>] (redhat-9.3, rhel-9, centos-9,
# rocky-9, almalinux-9, oraclelinux-9, ol9); normalise those to the el-tag form.
_RPM_DISTRO = re.compile(
    r"^(?:rhel|redhat|centos|rocky(?:linux)?|alma(?:linux)?|oracle(?:linux)?|ol)[-_ ]?(\d+)(?:[.](\d+))?$",
    re.I)

# Vendor of an rpm host → which affected `source`s to trust. The elN dist-tag is SHARED across the
# whole RHEL family (redhat/oracle/alma/rocky all tag el8_6), so the release stream alone cannot
# separate vendors: an Oracle ksplice fix (epoch 2) would otherwise leak into a Red Hat result and
# even become its remediation target. Scope the match to the host's own vendor + Red Hat as the
# authoritative rebuild baseline for the clones (whose own feeds can lag). CentOS has no feed of its
# own — it IS a RHEL rebuild — so it maps to Red Hat. `oracle` is NEVER pulled into a non-Oracle
# match (that is exactly where the ksplice noise lives). Unknown vendor → None → no source filter →
# the whole-family pool (unchanged legacy behaviour: best-effort coverage when no vendor is given).
_RPM_VENDOR = re.compile(r"^(rhel|redhat|centos|rocky|alma|oracle|ol)(?:linux)?(?:[-_. ]?\d.*)?$", re.I)
_VENDOR_SOURCES = {
    "rhel": ["redhat"], "redhat": ["redhat"], "centos": ["redhat"],
    "oracle": ["oracle", "redhat"], "ol": ["oracle", "redhat"],
    "alma": ["almalinux", "redhat"], "rocky": ["rocky", "redhat"],
}


def _rpm_sources(distro, namespace):
    """RHEL-family vendor → affected `source`s to match, or None (unknown → whole-family pool).
    `distro` (the distro= qualifier / release) wins; the purl namespace is the fallback."""
    for cand in (distro, namespace):
        m = _RPM_VENDOR.match(cand or "")
        if m:
            return _VENDOR_SOURCES[m.group(1).lower()]
    return None


def _el_streams(major, minors):
    """The RHEL streams a host is actually served by: the base major stream (elN — where Red Hat keys
    the major-stream/OVAL fix and the affected/won't-fix statements) plus each minor line the host is
    genuinely on. `minors` is that set of minor numbers (the package's own dist-tag minor and, when
    known, the host OS minor); pass None/empty for a base-only (elN) scope. OTHER minors are foreign
    EUS backport lines with independent release numbering (libxslt 1.1.32-8.el8_6 vs 1.1.32-6.4.el8_10)
    that the host never runs; including them makes the host look "below" a foreign line's
    higher-sorting build → false positives, so they stay out."""
    streams = [f"el{major}"]
    for mn in dict.fromkeys(m for m in (minors or ()) if m is not None):
        streams.append(f"el{major}_{mn}")
    return streams


def _rpm_streams(version, rel):
    """Resolve the RHEL stream set. The package's OWN `.elN_M` dist tag is authoritative: the host
    literally runs a build from that line, so a fix keyed to it applies directly — openssl
    1.1.1k-15.el8_6 vs the -17.el8_6 fix is the SAME line, even on an 8.10 host (Red Hat freezes the
    el8_6 tag and ships later fixes under it rather than rebuilding per minor). The host's OS minor
    from `distro=`/release is ADDED to the scope, never used to override the package's own line:
      - a bare `.el8` tag (base/AppStream packages not rebuilt per minor, e.g. postfix 3.5.8-7.el8)
        carries no minor of its own → it inherits the distro minor (else it resolves to just [elN]
        and misses elN_M fixes);
      - a fix that landed in the current OS minor still applies, so that minor stays in scope too.
    An earlier `max(build, distro)` collapsed both to the higher minor and dropped the frozen-tag
    line, silently missing those EUS fixes (false negative). The release is the full fallback when
    the version carries no tag at all."""
    rm = _EL_TAG.match(rel or "") or _RPM_DISTRO.match(rel or "")
    rmaj, rmin = (rm.group(1), rm.group(2)) if rm else (None, None)
    m = _DIST.search(version or "")
    if m:
        major, _, minor = m.group(1).partition("_")
        vmin = minor if minor.isdigit() else None                 # the package's own build minor
        omin = rmin if (rmaj == major and rmin and rmin.isdigit()) else None   # host OS minor
        return _el_streams(major, (vmin, omin))
    return _el_streams(rmaj, (rmin,)) if rmaj else None


# Parallel product lines that share a package NAME but that a host is never simultaneously on.
# Each is identified by a substring in the rpm RELEASE — carried on BOTH the host version and the
# stored `fixed` — and is numbered to sort ABOVE the regular build, so without this guard a regular
# host looks "below" such a fix, is falsely flagged, and it becomes the wrong remediation (e.g. a
# RHEL container-tools podman `4.9.4-…module+el8` steered to the OpenShift `5.2.x-…rhaos4.17.el8`).
# A fix is only comparable to a host carrying the SAME tag; a tag-less (regular) host skips them all.
# CENTRAL list — add a marker only after confirming it is a genuinely separate line (the package
# has both tagged and untagged builds), so a real fix is never wrongly skipped. Keep substrings long
# enough to be unambiguous (avoid short fragments that could hit a hash or an unrelated version).
_VARIANT_TAGS = (
    "_fips",      # FIPS-validated crypto (RHEL/Oracle) — epoch-bumped
    "ksplice",    # Oracle Ksplice live-patch stream
    "rhaos",      # Red Hat OpenShift (rhaos4.x) — its own podman/buildah/skopeo/cri-o/… builds
    "module",     # RHEL AppStream module co-rebuild (.module+elN) — a non-module host never runs it
)

# Layered products & special kernels carry a dist tag of the form elN<letters>: el9ap (Ansible
# Automation Platform), el8eap/el9eap (JBoss EAP), el9uek/el10uek (Oracle UEK kernel), el7ost/el8ost
# (OpenStack), el7sat/el8sat (Satellite), el9cp/el8cp (OpenShift), el8jbcs/el8jws (JBoss) … — each a
# separate line that ships its OWN, often much newer build (python3-requests 2.32.2-1.el9ap vs the
# base 2.25.1-9.el9). A base build is ONLY ever elN or elN_M, so a letter right after the digits is
# never the base line (nor a hex hash — `l` isn't hex); such a fix is comparable only to a host that
# itself carries the tag. The tag rides in the installed EVR, so a host genuinely on the product
# matches its own fixes, while a base host skips them.
_LAYERED_RE = re.compile(r"el\d+[a-z]+")


def _variant(evr):
    """The parallel product line an rpm EVR belongs to (a :data:`_VARIANT_TAGS` marker or a layered
    elN<letters> dist tag), or None for a regular build. A fix is only comparable to a host of the
    same variant; the marker rides in the version string, so host version and stored `fixed` carry
    it."""
    r = (evr or "").lower()
    tag = next((t for t in _VARIANT_TAGS if t in r), None)
    if tag:
        return tag
    m = _LAYERED_RE.search(r)
    return m.group(0) if m else None


def _mod_stream(rpmmod):
    """AppStream module identity `name:stream` from glance's `rpmmod` qualifier value
    (`nodejs:18:9070…:rhel9` → `nodejs:18`), or None. Only name:stream is compared — the
    version:context tail differs per rebuild and must not enter the match (issue #35)."""
    if not rpmmod:
        return None
    parts = rpmmod.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 and parts[0] and parts[1] else None


# ── SUSE / SLE ─────────────────────────────────────────────────────────────────────────────
# SUSE is a wholly separate RPM world from the RHEL family and the matcher had no lane for it:
# `_rpm_streams` only understands `.elN` dist tags + RHEL distros, so a SLES host resolved to
# release=None → the deb/ecosystem `release IS NULL` catch-all. That fetched the wrong pool — it
# dropped every correctly-released SLES row (they carry `sles15sp3`, `sle-module-…`, …) and let in
# the release-less noise, so a SLES-15.3 `libopenssl1_1` fell back to the SOURCE `openssl` and
# matched SUSE Liberty Linux (`sll*`, SUSE's RHEL REBUILD — `.el` versions) → a bogus
# `3.5.5-4.el10_2` remediation. SUSE needs its own scoping:
#   • the maintenance CODESTREAM in the EVR (`…-150200.11.103.1` → 150200) is the authoritative
#     comparison key. A fix is only comparable to a host on the SAME codestream; `sll*`/`.el` builds
#     and cross-SP `150400` builds carry a different one (or none) and drop out.
#   • Within a codestream, base and the extended-support lanes (LTSS / SAP / HPC / RT / …) share ONE
#     monotonically increasing build sequence — base `sles15sp3` ends at -150200.11.51.1, then
#     `sles-ltss15sp3` CONTINUES the SAME sequence to .75, .97, .103. So a host's own build number
#     alone places it: a `.103.1` host has every fix up to .103 regardless of which lane's label
#     carries it. We therefore INCLUDE the extended-support lanes (unlike RHEL EUS, whose minor
#     streams have independent numbering) and let the build compare decide.
#   • A SUSE `known_affected` with no fix means "no fix on the BASE lane" — but the same CVE is
#     usually fixed on LTSS. A host at an LTSS build is patched, so an open `affected` row is
#     honoured only when the CVE has NO reachable fix in scope (see `suse_patched` in match()).
#   • SLL (RHEL rebuild), SLED (desktop), SES (storage), Leap/Tumbleweed, CaaSP, MicroOS, SUSE
#     Manager are DIFFERENT products, not a SLES host's lanes.
_SUSE_HOST_RE = re.compile(r"^(?:sles|sled|sle[-_]|suse|opensuse|leap|caasp|tumbleweed)", re.I)
_SUSE_CS_RE = re.compile(r"-(\d{6})\.\d")          # SLE maintenance codestream: -150200.11.103.1
_SUSE_MAJSP_RE = re.compile(r"(\d+)(?:[.\-]?(?:sp)?(\d+))?\s*$", re.I)   # trailing major(+sp)


def _is_suse(distro, namespace, version):
    """True when the component is a SUSE/SLE host — by distro/namespace or a SUSE codestream EVR."""
    return bool(_SUSE_HOST_RE.match(distro or "") or _SUSE_HOST_RE.match(namespace or "")
                or _SUSE_CS_RE.search(version or ""))


def _suse_cs(evr):
    """The SLE maintenance codestream in an EVR (`1.1.1d-150200.11.103.1` → '150200'), or None
    for a non-SUSE build (`3.5.5-4.el10_2` → None)."""
    m = _SUSE_CS_RE.search(evr or "")
    return m.group(1) if m else None


def _suse_majsp(s):
    """(major, sp) from a SUSE distro or release lane: 'sles-15.3' → ('15','3');
    'sle-module-basesystem15sp3' → ('15','3'); 'sles15' → ('15', None)."""
    m = _SUSE_MAJSP_RE.search(s or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def _suse_family(lane, host_prod):
    """True when the SUSE release lane belongs to the host's product family. `sll*` (RHEL rebuild),
    `suse-manager-*`, `suse-microos*`, `leap*`, `ses*`, `caasp*`, openSUSE and Tumbleweed are
    different products (none start with `sle`); a SLES host runs the `sle*`/`sles*` server family
    incl. its LTSS/SAP/HPC extended-support lanes, plus the shared `sle-module-*`; SLED (desktop)
    is its own product."""
    l = (lane or "").lower()
    if l.startswith("sle-module-"):
        return True                                  # modules are shared across SLE products
    if not l.startswith("sle"):
        return False                                 # sll / suse-* / leap / ses / caasp / … — other
    return l.startswith("sled") == (host_prod == "sled")


def _suse_scope(lane, fixed, host_prod, host_maj, host_cs):
    """Is a SUSE affected row in scope for the host? Same product family, same SLE major, and — for
    a fix — the host's build codestream (`…-150200.…`). Extended-support lanes are IN scope; the
    build number compare (and `suse_patched`) does the rest."""
    if not _suse_family(lane, host_prod):
        return False
    lmaj, _lsp = _suse_majsp(lane)
    if host_maj and lmaj and lmaj != host_maj:
        return False
    if fixed and host_cs and _suse_cs(fixed) != host_cs:
        return False
    return True


def _lane(ptype, version, quals, release=None):
    """→ (ecosystem, release) for the affected lookup. `release` may be a list (rpm streams)."""
    if ptype == "rpm":
        return "rpm", _rpm_streams(version, release or quals.get("distro"))
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
    """rows for one CVE: list of (src, introduced, fixed, last_affected, scheme, status, fix_kb).

    Group by ``introduced`` (= one affected range). Within a group the host counts as
    patched as soon as it reaches ANY of the group's fix builds — so parallel fix tracks
    (Windows security-only vs monthly rollup, with different build numbers) don't
    false-positive. Distinct ranges (different ``introduced``) are OR'd as usual.
    Returns [(src, status, fixed, fix_kb, scheme), …] or [] when not vulnerable.
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
                hits.append((rep[0], rep[5], rep[2], rep[6], scheme))
        elif lasts:
            if any(iv <= lv for _, lv in lasts):
                hits.append((lasts[0][0][0], lasts[0][0][5], None, lasts[0][0][6], scheme))
        elif had_bounds:
            continue                                       # had a fixed/last bound but it didn't
            #                                                parse → can't decide → don't flag (no FP)
        else:
            hits.append((group[0][0], group[0][5], None, group[0][6], scheme))  # no bound → open-ended
    return hits


# ── Microsoft CPE editions ───────────────────────────────────────────────────────────────────
# NVD/MSRC file some Microsoft products under BOTH a generic base product name (`sql_server`) and
# year-suffixed names (`sql_server_2019`, `sql_server_2022`, …). Application catalogers (glance) emit
# the GENERIC name with the build in the version field, so every edition-scoped CVE filed under a
# suffixed name is silently missed — a SQL Server 2019 host on `sql_server:15.0.2000.5` never matches
# the `sql_server_2019` rows (issue #44). SQL Server's editions map cleanly to the leading MAJOR
# (2017/19/22/25 = 14/15/16/17), so we match the whole family scoped to the host's major — a 16.x fix
# can never reach a 15.x host, so there is no cross-edition false positive.
# Deliberately SQL-Server-only for now; the other split families need their own edition logic and are
# NOT safe under a bare major key:
#   - visual_studio: major is noisy (2019 rows carry majors 16/17/8; the generic product mixes
#     11/12/14 and malformed builds) — a major key would cross-contaminate editions.
#   - azure_devops_server: versioned by DATE builds (20230601.x), not a major at all.
#   - office: editions are build-RANGES (16.0.5xxx=2016, 16.0.10xxx=2019, …), not a major.
#   - windows_*: glance scans the exact release from the registry, so there is no generic name to
#     miss (verified: a windows_server_2022 host matches its own rows, no FN).
_MS_MAJOR_FAMILIES = ("sql_server",)
# SQL Server release major → marketing year, the exact `<base>_<year>` product NVD files edition CVEs
# under. Used to look those rows up by EXACT cpe23 key (index scan) instead of a `LIKE base%` prefix:
# the affected.cpe23 btree is a default-collation index, so `LIKE 'prefix%'` does NOT use it and falls
# back to a full 14M-row seq scan (~40s per Microsoft match). Enumerating the host's two concrete
# products (generic base + its year edition) keeps the lookup on the index.
_MS_SQL_YEAR = {"13": "2016", "14": "2017", "15": "2019", "16": "2022", "17": "2025"}


def _ms_family(product):
    """The Microsoft major-versioned family a CPE product belongs to (`sql_server_2019` → `sql_server`;
    `sql_server` → `sql_server`), or None. Only the bare base or a `<base>_<year>` variant qualifies,
    so `sql_server_management_studio` (a different product) stays out."""
    for base in _MS_MAJOR_FAMILIES:
        if product == base or re.match(re.escape(base) + r"_\d{4}$", product or ""):
            return base
    return None


def _ms_major(version):
    """Leading numeric component of a version — the edition key for a major-versioned MS family
    (`15.0.2000.5` → '15'), or None."""
    m = re.match(r"\s*(\d+)", version or "")
    return m.group(1) if m else None


def _ms_family_products(fam, host_major):
    """The concrete CPE product names to look up for a Microsoft edition family on a host of the given
    major: the generic base plus the host major's year edition (`sql_server` + `sql_server_2019` for
    major 15). Both are exact names so the lookup stays on the cpe23 index; the generic rows are
    still major-filtered per-row in match_cpe (they mix majors), the year edition is inherently
    single-major."""
    prods = [fam]
    if fam == "sql_server":
        yr = _MS_SQL_YEAR.get(host_major or "")
        if yr:
            prods.append(f"{fam}_{yr}")
    return prods


def match_cpe(conn, cpe, version=None, curations=None):
    """Match a CPE 2.3 string (from a binary/registry cataloger) against the cpe lane."""
    key, cv = parse_cpe(cpe)
    version = version or cv
    if not key:
        raise ValueError("not a cpe 2.3 string")
    if not version:
        raise ValueError("no version (give cpe:…:<version>:… or a second arg)")
    if curations is None:
        curations = load_curations(conn)
    pkg = key.split(":")[4]
    # Microsoft edition family: fetch the WHOLE family (generic + every year-suffixed sibling) and
    # scope to the host's major below, so a generic-scanned host still matches the year-filed CVEs
    # without pulling a foreign edition's fixes. Otherwise: the exact cpe23 key.
    fam = _ms_family(pkg)
    host_major = _ms_major(version) if fam else None
    cols = ("SELECT cve_id, source, introduced, fixed, last_affected, version_scheme, status, fix_kb, "
            "split_part(cpe23, ':', 5) FROM affected WHERE coord = 'cpe' ")
    if fam:                                            # exact sibling keys → index scan (not LIKE)
        p = key.split(":")
        fam_keys = [":".join(p[:4] + [prod] + p[5:]) for prod in _ms_family_products(fam, host_major)]
        sql, params = cols + "AND cpe23 = ANY(%s)", (fam_keys,)
    else:
        sql, params = cols + "AND cpe23 = %s", (key,)
    by_cve = {}
    with conn.cursor() as cur:
        cur.execute(sql, params)
        for cid, src, intro, fixed, last, scheme, status, kb, product in cur.fetchall():
            if fam:
                if _ms_family(product) != fam:         # a real family sibling only (not …_studio)
                    continue
                rmaj = _ms_major(fixed) or _ms_major(intro)
                if host_major and rmaj and rmaj != host_major:
                    continue                           # foreign edition — different major line
            ctx = _curate(cid, {"coord": "cpe", "ecosystem": None, "package": pkg, "cpe23": key,
                                "release": None, "source": src, "status": status,
                                "fixed": fixed, "introduced": intro, "last_affected": last}, curations)
            if ctx is None:
                continue                                          # suppressed by a curation rule
            by_cve.setdefault(cid, []).append(
                (src, ctx["introduced"], ctx["fixed"], ctx["last_affected"], scheme, ctx["status"], kb))
    return {cid: hits for cid, rows in by_cve.items() if (hits := _cpe_verdict(version, rows))}


def match(conn, purl, version=None, release=None, curations=None):
    """Return {cve_id: [(source, status, fixed, fix_kb, scheme), …]} for the vulnerable hits."""
    if curations is None:
        curations = load_curations(conn)
    if purl.startswith("cpe:"):
        return match_cpe(conn, purl, version, curations)
    ptype, name, pv, quals, namespace = parse_purl(purl)
    version = version or pv
    if not version:
        raise ValueError("no version (give pkg@version or a second arg)")
    if ptype == "rpm" and quals.get("epoch") and ":" not in version:
        version = f"{quals['epoch']}:{version}"      # RPM epoch governs the compare (1:3.2 > 3.9)
    eco, rel = _lane(ptype, version, quals, release)
    # binary-first: OVAL/CSAF list every BINARY rpm with its OWN correctly-versioned rows (perl-B's
    # own 1.80 builds, vim-common's fix build). Prefer them; the SOURCE package (the `upstream=`
    # qualifier) is only a FALLBACK for binaries that have no rows of their own — deb, where advisories
    # are source-keyed, or an rpm binary OVAL didn't test. Querying the source when the binary HAS its
    # own rows would compare the binary's own version against the SOURCE's fix version (perl-B 1.80 vs
    # perl 5.32.1) → a false positive (issue #36).
    # unquote: glance percent-encodes `+` (and other reserved chars) in the purl name, so libstdc++
    # arrives as `libstdc%2B%2B`; the affected table stores the decoded name (`libstdc++`), so the
    # binary lookup must decode too or it silently misses every +-bearing package (libstdc++, gcc-c++,
    # ImageMagick-c++ …) and falls through to the source.
    binary = (unquote(purl.split("?", 1)[0].split("@", 1)[0].rsplit("/", 1)[-1]).lower()
              if ptype in ("rpm", "deb") else None)
    primary = binary or name.lower()
    source_pkg = (quals.get("upstream") or "").lower()
    # SUSE/SLE hosts get their own lane (codestream + support-line scoping below); they are not part
    # of the RHEL-family elN pool and must never be vendor-scoped to it.
    suse = ptype == "rpm" and _is_suse(release or quals.get("distro"), namespace, version)
    host_cs = _suse_cs(version) if suse else None
    _hd = (release or quals.get("distro") or namespace or "").lower()
    host_prod = "sled" if _hd.startswith("sled") else "sles"
    host_maj = _suse_majsp(release or quals.get("distro") or "")[0] if suse else None
    # rpm: scope the shared elN pool to the host's own vendor (+ RH baseline) so a clone's
    # vendor-specific rows (Oracle ksplice, …) don't leak in. Unknown vendor → None → no filter.
    sources = _rpm_sources(release or quals.get("distro"), namespace) if (ptype == "rpm" and not suse) else None
    base = ("SELECT cve_id, source, release, introduced, fixed, last_affected, "
            "version_scheme, status, status_raw, module_stream FROM affected "
            "WHERE ecosystem = %s AND lower(package) = %s ")
    if suse:                                         # SUSE → fetch its own rows; never the RHEL-
        #   rebuild `sll*` product nor the release-less noise. Precise scoping is done per-row below.
        tail, extra = "AND source = 'suse' AND release IS NOT NULL AND release NOT LIKE 'sll%%'", ()
    elif isinstance(rel, list):                     # rpm → match the major + minor streams
        tail, extra = "AND release = ANY(%s)", (rel,)
        if sources is not None:                     # scope to the host's vendor (+ RH baseline)
            tail, extra = tail + " AND source = ANY(%s)", extra + (sources,)
    else:                                           # deb / ecosystem → exact release or NULL
        tail, extra = "AND (release = %s OR (%s::text IS NULL AND release IS NULL))", (rel, rel)
    sql = base + tail

    def _fetch(pkg):
        with conn.cursor() as cur:
            cur.execute(sql, (eco, pkg) + extra)
            return cur.fetchall()

    rows = _fetch(primary)
    if not rows and source_pkg and source_pkg != primary:
        rows = _fetch(source_pkg)        # source fallback (deb; or an rpm binary OVAL didn't test)
    host_var = _variant(version)         # fips/ksplice host only compares to its own variant's fixes
    # AppStream module stream (nodejs:18, php:8.0) from glance's `rpmmod` qualifier. The streams are
    # parallel, independently maintained lines — a host on nodejs:10 must NOT be flagged against a
    # nodejs:12/24 fix (`10.x < 24.x`, both `.module`). A module fix is only comparable to a host on
    # the SAME stream. Dormant when absent: a non-modular host (or glance not yet emitting rpmmod)
    # has no stream → no filtering, current behaviour (issue #35).
    host_stream = _mod_stream(quals.get("rpmmod"))
    # Red Hat VEX: a per-binary `not_affected` ("vulnerable code not present") overrides the
    # product-level "affected" statement for the same package. A module co-rebuild lists every rpm in
    # the stream as affected, but Red Hat marks the ones without the vulnerable code not_affected —
    # CVE-2026-4176 is affected on `perl` yet not_affected on every perl sub-module. Honour it so those
    # bystanders (which carry only an unbounded "affected", no fix) are not flagged; a real fix row is
    # untouched (a shipped fix already means the code was there).
    not_affected = {r[0] for r in rows if r[7] == "not_affected"}   # r[0]=cve_id, r[7]=status
    # SUSE: a host that MEETS a reachable fix (its build >= a same-codestream fix) is patched, even
    # when the base lane also carries a fix-less `known_affected` for that CVE (base support ended,
    # LTSS shipped the fix). Collect those CVEs so the open `affected` rows in the loop don't
    # re-flag an already-patched host.
    suse_patched = set()
    if suse:
        for r in rows:
            if not r[4] or not _suse_scope(r[2], r[4], host_prod, host_maj, host_cs):
                continue                                          # r[2]=release, r[4]=fixed
            hv, fv = _v(r[6], _strip_epoch(version)), _v(r[6], _strip_epoch(r[4]))   # r[6]=scheme
            if hv is not None and fv is not None and hv >= fv:
                suse_patched.add(r[0])
    findings = {}
    for cid, src, rel_row, intro, fixed, last, scheme, status, sraw, mstream in rows:
        if sraw in _SKIP_RAW:            # deprioritised vendor fix-state (Red Hat "Fix deferred")
            continue
        if (rv := _variant(fixed)) is not None and rv != host_var:
            continue                     # foreign parallel line (fips/ksplice) — never the host's
        if host_stream and mstream and mstream != host_stream:
            continue                     # foreign module stream (nodejs:14 vs the host's :18) — #35
        if suse:
            if not _suse_scope(rel_row, fixed, host_prod, host_maj, host_cs):
                continue                 # foreign SUSE product / major / codestream
            if status == "affected" and fixed is None and cid in suse_patched:
                continue                 # base "known_affected" but host meets an LTSS/SAP fix
        ctx = _curate(cid, {"coord": "purl", "ecosystem": eco, "package": primary, "cpe23": None,
                            "release": rel_row, "source": src, "status": status,
                            "fixed": fixed, "introduced": intro, "last_affected": last}, curations)
        if ctx is None:
            continue                                              # suppressed by a curation rule
        if ctx["status"] == "affected" and ctx["fixed"] is None and cid in not_affected:
            continue                     # VEX not_affected overrides the co-rebuild "affected"
        if is_vulnerable(scheme, version, ctx["introduced"], ctx["fixed"], ctx["last_affected"], ctx["status"]):
            findings.setdefault(cid, []).append((src, ctx["status"], ctx["fixed"], None, scheme))
    return findings


def remediation(findings: dict):
    """The single highest fix that closes a matched component's fixable CVEs, and which CVE
    demands it — so a caller can say "upgrade to X → closes N". `findings` is the dict match()
    returns ({cve: [(src, status, fixed, fix_kb, scheme), …]}).

    Per CVE we take its one fix (first non-NULL). The max is computed with ONE comparator: rpm/deb
    keep their EVR comparator (epoch matters), everything else orders as `generic` (MavenVersion
    covers the cpe generic/semver/pep440 mix + pypi/npm — all plain X.Y.Z). CVEs with no fix are
    counted in `unfixed` (an upgrade can't close them), so "closes all" never lies.
    Returns None for an empty (compliant) set.
    """
    if not findings:
        return None
    fixable, unfixed = [], 0
    for cve, hits in findings.items():
        cand = [h for h in hits if h[2]]                    # hits that carry a fix
        if not cand:
            unfixed += 1
            continue
        # per CVE take its HIGHEST fix, not an arbitrary first: Red Hat lists the same CVE across
        # several in-scope lines (flatpak's el9_6.1 EUS backport alongside the el9-base el9_8.1), and
        # the newest build is the real upgrade target — the first would surface a stale, insufficient
        # fix. Same comparator choice as the cross-CVE max below.
        sc = "rpm" if any(h[4] == "rpm" for h in cand) else "deb" if any(h[4] == "deb" for h in cand) else "generic"
        parse = [h for h in cand if _v(sc, h[2]) is not None]
        pick = max(parse, key=lambda h: _v(sc, h[2])) if parse else cand[0]
        fixable.append((cve, pick[2],
                        next((h[3] for h in hits if h[3]), None),          # fix_kb
                        pick[4]))                                          # scheme
    if not fixable:
        return {"fixed": None, "fix_kb": None, "cve": None, "closes": 0, "unfixed": unfixed}
    schemes = {s for *_, s in fixable}
    comp = "rpm" if "rpm" in schemes else "deb" if "deb" in schemes else "generic"
    parseable = [(cve, f, kb) for cve, f, kb, _s in fixable if _v(comp, f) is not None]
    if not parseable:                                       # nothing comparable → don't invent a max
        return {"fixed": None, "fix_kb": None, "cve": None, "closes": len(fixable), "unfixed": unfixed}
    top = max(parseable, key=lambda x: _v(comp, x[1]))
    return {"fixed": top[1], "fix_kb": top[2], "cve": top[0], "closes": len(fixable), "unfixed": unfixed}
