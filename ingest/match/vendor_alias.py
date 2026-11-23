"""Distro vendor aliases for rpm components: the one reviewed map between how inventory names a
distro and how vDB stores that vendor's advisory rows.

Scanners (glance) put the host's os-release ID in the purl namespace and the `distro=` qualifier:
`pkg:rpm/ol/brotli@1.0.6-5.el8_10?distro=ol-8.10`, `pkg:rpm/sles/libbrotlicommon1?distro=sles-15.7`.
vDB stores each vendor's rows under its own namespace: `pkg:rpm/oracle/…` (Oracle OVAL + its
Red Hat-inherited rows) and `pkg:rpm/suse/…` (SUSE CSAF/VEX, incl. openSUSE Leap lanes). A literal
namespace join therefore never finds the vendor's evidence for an `ol` or `sles` host (IA-2072).

Only reviewed aliases live here; an unknown value resolves to None, never to a guessed vendor.
"""
import re

# Canonical vendor of every RHEL-family value the matcher already recognised, each with an optional
# `linux` suffix (rockylinux, almalinux, oraclelinux, …) exactly as the former `_RPM_VENDOR` did.
_RHEL_FAMILY_IDS = {
    "rhel": "redhat", "redhat": "redhat", "centos": "centos",
    "alma": "almalinux", "rocky": "rocky", "oracle": "oracle", "ol": "oracle",
}
VENDOR_ALIASES = {f"{alias}{suffix}": vendor
                  for alias, vendor in _RHEL_FAMILY_IDS.items() for suffix in ("", "linux")}
VENDOR_ALIASES.update({
    # Oracle Linux — display-name forms and the legacy "Oracle Enterprise Linux" abbreviation.
    "oracle-linux": "oracle", "oracle_linux": "oracle", "oel": "oracle",
    # SUSE — os-release IDs of SLES, SLED, SLES for SAP and openSUSE. SUSE host detection and
    # product/codestream scoping stay in the matcher's own SUSE lane; this only names the vendor.
    "suse": "suse", "sles": "suse", "sled": "suse", "sles_sap": "suse",
    "opensuse": "suse", "opensuse-leap": "suse", "opensuse-tumbleweed": "suse",
})
RHEL_FAMILY = frozenset({"redhat", "centos", "almalinux", "rocky", "oracle"})
# Vendors whose inventory namespace is rewritten to the namespace vDB stores their rows under.
# Deliberately limited to reviewed cases; other namespaces are passed through unchanged.
_VDB_NAMESPACE = {"oracle": "oracle", "suse": "suse"}

# <id>[<sep>]<major>[.<minor>][<rest>] — the id is the shortest prefix that leaves a version tail.
_DISTRO = re.compile(r"^([a-z][a-z_-]*?)(?:[-_.]?(\d+)(?:\.(\d+))?(.*))?$")


def _parts(value):
    """(id, major, minor, rest) of a distro/namespace value; spaces fold to '-' so display names
    (`Oracle Linux 8.10`) parse like IDs (`oracle-linux-8.10`). None when it isn't id[-version]."""
    s = re.sub(r"\s+", "-", (value or "").strip().lower())
    m = _DISTRO.match(s)
    return m.groups() if m else None


def distro_vendor(value):
    """Canonical vendor ('oracle', 'suse', 'redhat', …) of a namespace or distro value
    (`ol`, `ol-8.10`, `Oracle Linux 8.10`, `sles-15.7`), or None when it isn't a reviewed alias."""
    p = _parts(value)
    return VENDOR_ALIASES.get(p[0]) if p else None


def rhel_family_release(value):
    """(major, minor|None) of a RHEL-family distro value (`ol-8.10` → ('8', '10'),
    `oracle-linux-9` → ('9', None)), or None for a non-RHEL-family or version-less value."""
    p = _parts(value)
    if not p or VENDOR_ALIASES.get(p[0]) not in RHEL_FAMILY or not p[1] or p[3]:
        return None
    return p[1], p[2]


def canonical_namespace(namespace):
    """The vDB namespace for an rpm purl namespace (`ol` → `oracle`, `sles` → `suse`);
    any other value is returned unchanged."""
    return _VDB_NAMESPACE.get(distro_vendor(namespace), namespace)


def canonical_purl(purl):
    """An rpm purl with its namespace rewritten to vDB's (`pkg:rpm/ol/brotli@…?distro=ol-8.10` →
    `pkg:rpm/oracle/brotli@…?distro=ol-8.10`). Version and qualifiers are kept as they are; a
    non-rpm or namespace-less purl, or an unreviewed namespace, is returned unchanged."""
    if not (purl or "").lower().startswith("pkg:rpm/"):
        return purl
    body = purl[len("pkg:rpm/"):]
    namespace, sep, rest = body.partition("/")
    if not sep or "@" in namespace or "?" in namespace:
        return purl
    canonical = canonical_namespace(namespace)
    return purl if canonical == namespace else f"pkg:rpm/{canonical}/{rest}"
