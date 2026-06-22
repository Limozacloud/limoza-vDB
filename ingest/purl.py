"""Canonical Package URL construction — single source of truth.

Wraps ``packageurl-python`` (serialization + validation) and adds the
per-ecosystem name normalization the library does NOT do itself — notably
PyPI's PEP 503 rule where runs of ``-``, ``_`` and ``.`` collapse to a single
``-`` (the library handles ``_`` but leaves ``.`` untouched).

Transforms should build purls through here instead of hand-rolling f-strings,
so the same package gets the same canonical purl regardless of source.
"""
import re
from typing import Optional

from packageurl import PackageURL

_PYPI_NAME = re.compile(r"[-_.]+")


def make_purl(
    ptype: str,
    name: str,
    *,
    namespace: Optional[str] = None,
    qualifiers: Optional[dict] = None,
    subpath: Optional[str] = None,
) -> Optional[str]:
    """Return a canonical purl string for the given parts, or None if name is empty.

    Applies PyPI name normalization (PEP 503) that packageurl-python omits.
    """
    if not name:
        return None
    if ptype == "pypi":
        name = _PYPI_NAME.sub("-", name).lower()
    return PackageURL(
        type=ptype,
        namespace=namespace or None,
        name=name,
        qualifiers=qualifiers or None,
        subpath=subpath or None,
    ).to_string()


def distro_purl(ptype: str, vendor: str, name: str, distro: Optional[str] = None) -> Optional[str]:
    """purl for an OS-distro package: ``pkg:<ptype>/<vendor>/<name>[?distro=…]``.

    Convenience over :func:`make_purl` for the rpm/deb/apk distro sources.
    """
    return make_purl(ptype, name, namespace=vendor,
                     qualifiers={"distro": distro} if distro else None)


def normalize_purl_string(purl: str) -> Optional[str]:
    """Round-trip an existing purl string into canonical form.

    Used for source-provided purls (e.g. OSV's ``package.purl``) so they match
    the ones we build ourselves. Malformed strings are returned unchanged rather
    than dropped.
    """
    if not purl:
        return None
    try:
        p = PackageURL.from_string(purl)
    except Exception:
        return purl
    if p.type == "pypi" and p.name:
        return make_purl(
            "pypi", p.name,
            namespace=p.namespace,
            qualifiers=dict(p.qualifiers) or None,
            subpath=p.subpath,
        )
    return p.to_string()


# OSV/GHSA ecosystem string -> purl type, for single-name ecosystems.
_ECO_SIMPLE = {
    "pypi":           "pypi",
    "rubygems":       "gem",
    "ruby":           "gem",
    "nuget":          "nuget",
    "crates.io":      "cargo",
    "cargo":          "cargo",
    "hex":            "hex",
    "erlang":         "hex",
    "pub":            "pub",
    "github actions": "githubactions",
    "swift":          "swift",
}


def ecosystem_purl(ecosystem: str, name: str, hint: str = "") -> Optional[str]:
    """Map an OSV/GHSA ``(ecosystem, name)`` to a canonical purl.

    If ``hint`` (a source-provided purl string) is given, it is normalized and
    used directly. Returns None for unknown ecosystems or empty input.
    """
    if hint:
        return normalize_purl_string(hint)
    if not ecosystem or not name:
        return None
    eco = ecosystem.strip().lower()

    if eco == "npm":
        if name.startswith("@"):
            scope, _, pkg = name[1:].partition("/")
            return make_purl("npm", pkg, namespace="@" + scope) if pkg else None
        return make_purl("npm", name)
    if eco == "go":
        ns, _, n = name.rpartition("/")
        return make_purl("golang", n or name, namespace=ns or None)
    if eco == "maven":
        sep = ":" if ":" in name else "/"
        group, found, artifact = name.partition(sep)
        return make_purl("maven", artifact, namespace=group) if found and artifact else None
    if eco in ("packagist", "composer"):
        ns, _, n = name.partition("/")
        return make_purl("composer", n, namespace=ns) if n else make_purl("composer", ns)
    if eco in _ECO_SIMPLE:
        return make_purl(_ECO_SIMPLE[eco], name)
    return None
