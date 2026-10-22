"""Temporary compatibility aliases for inventory identities emitted before Glance upgrades.

These aliases are deliberately narrow. They run only when a component was already supplied
to ``/match`` and its own PURL/CPE produced no finding; they never manufacture a component for
a host that did not inventory it. The next Glance release should emit the canonical identities
directly, at which point these mappings can be retired after inventory refreshes.
"""
from __future__ import annotations

import re

_LOG4J_JAR = re.compile(r"^log4j-(\d+(?:\.\d+)+)\.jar$", re.I)
# @next/env is the Next.js monorepo's environment-variable loader. It is released in lockstep with
# the `next` package (identical version) and carries no advisories of its own, so a Next.js CVE
# (filed against `next`) is missed when an inventory reports only @next/env. Map it to `next`.
# Group 1 captures the version straight from the purl when the component has no separate version.
_NEXT_ENV = re.compile(r"(?i)^pkg:npm/@next/env(?:@([^?]+))?(?:\?|$)")


def _purl_base(value: str) -> str:
    return value.split("?", 1)[0].split("@", 1)[0].lower()


def _numeric_parts(value: str) -> tuple[int, ...] | None:
    parts = value.split(".")
    if not parts or not all(part.isdigit() for part in parts):
        return None
    numbers = [int(part) for part in parts]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    return tuple(numbers)


def _same_version(left: str, right: str) -> bool:
    left_parts, right_parts = _numeric_parts(left), _numeric_parts(right)
    return left_parts is not None and left_parts == right_parts


def _names(component: dict) -> set[str]:
    values = {str(component.get("name") or "").strip().lower()}
    path = str(component.get("path") or "").strip()
    if path:
        values.add(path.replace("\\", "/").rsplit("/", 1)[-1].lower())
    return values - {""}


def temporary_cpe_alias(component: dict, version: str) -> tuple[str, str] | None:
    """Map a verified legacy inventory identity to its canonical CPE.

    Returns ``(identity, reason)`` or ``None`` — the identity is a canonical CPE, or a purl when
    aliasing to another package in the same ecosystem. The caller must still ask the regular
    matcher whether vDB has an applicable affected-version row for that identity.
    """
    version = (version or "").strip()
    raw_purl = str(component.get("purl") or "")

    # @next/env → next (same version). Checked before the version guard so the version can come
    # from the purl itself when the component carries no separate version field.
    next_env = _NEXT_ENV.match(raw_purl)
    if next_env:
        next_version = version or (next_env.group(1) or "").strip()
        if next_version:
            return f"pkg:npm/next@{next_version}", "legacy_next_env"

    if not version:
        return None
    purl = _purl_base(raw_purl)
    names = _names(component)

    if purl == "pkg:maven/log4j/log4j":
        return f"cpe:2.3:a:apache:log4j:{version}:*:*:*:*:*:*:*", "legacy_maven_log4j"
    for name in names:
        match = _LOG4J_JAR.fullmatch(name)
        if match and _same_version(match.group(1), version):
            return f"cpe:2.3:a:apache:log4j:{version}:*:*:*:*:*:*:*", "legacy_log4j_filename"

    if purl == "pkg:generic/curl" or "curl.exe" in names:
        return f"cpe:2.3:a:haxx:curl:{version}:*:*:*:*:*:*:*", "legacy_curl"

    if purl == "pkg:generic/odbc-driver-sql-server" or "msodbcsql17.dll" in names or "msodbcsql18.dll" in names:
        return (
            f"cpe:2.3:a:microsoft:odbc_driver_for_sql_server:{version}:*:*:*:*:windows:*:*",
            "legacy_sql_odbc_driver",
        )
    if purl == "pkg:generic/oledb-driver-sql-server" or "msoledbsql.dll" in names:
        return (
            f"cpe:2.3:a:microsoft:ole_db_driver_for_sql_server:{version}:*:*:*:*:*:*:*",
            "legacy_sql_ole_db_driver",
        )
    return None
