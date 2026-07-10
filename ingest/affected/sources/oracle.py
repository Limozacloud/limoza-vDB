"""Oracle Linux affected — inherits Red Hat status (RHEL rebuild, el5+; UEK ships as
`kernel-uek*` so it never matches an inherited `kernel` row) PLUS Oracle's own OVAL
per-package fix criteria, which covers UEK and anything else Oracle-specific that Red
Hat never lists (Red Hat has no idea UEK exists).

OVAL <criterion comment="X is earlier than Y"/> already carries the fix EVR directly in
the human-readable comment — no need to resolve test_ref against the separate
<tests>/<objects>/<states> sections. The EVR's dist tag (.el8uek, .el9, …) gives the
release, exactly like `_dist_tag` in the Red Hat extractor.
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ingest.affected import row
from ingest.affected import status as st
from ingest.affected.sources._clone import inherit
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "oracle"

_DIST = re.compile(r"\.el(\d+)")
_FIX = re.compile(r"^([\w.+-]+) is earlier than (\S+)$")


def _lt(e) -> str:
    return e.tag.split("}")[-1]


def _walk_criteria(node, out: list) -> None:
    """Collect (package, evr) pairs from every fix-test criterion in this subtree,
    regardless of AND/OR nesting (arch-specific branches repeat the same pair)."""
    for child in node:
        tag = _lt(child)
        if tag == "criterion":
            m = _FIX.match(child.get("comment") or "")
            if m:
                out.append((m.group(1), m.group(2)))
        elif tag == "criteria":
            _walk_criteria(child, out)


def _oval_rows(f: Path):
    for _, elem in ET.iterparse(str(f), events=("end",)):
        if _lt(elem) != "definition" or elem.get("class") != "patch":
            continue
        meta = next((c for c in elem if _lt(c) == "metadata"), None)
        crit = next((c for c in elem if _lt(c) == "criteria"), None)
        if meta is None or crit is None:
            elem.clear()
            continue
        adv = next((c for c in meta if _lt(c) == "advisory"), None)
        cves = [normalize(c.text or "") for c in (adv or []) if _lt(c) == "cve"]
        cves = [c for c in cves if c]
        pairs: list = []
        _walk_criteria(crit, pairs)
        elem.clear()
        if not cves or not pairs:
            continue
        seen = set()
        for pkg, evr in pairs:
            if (pkg, evr) in seen:
                continue
            seen.add((pkg, evr))
            m = _DIST.search(evr)
            if not m:
                continue
            release = f"el{m.group(1)}"
            for cid in cves:
                yield row(
                    cve_id=cid, coord="purl", ecosystem="rpm", package=pkg,
                    purl=f"pkg:rpm/oracle/{pkg}", release=release, introduced="0",
                    fixed=evr, version_scheme="rpm", status=st.FIXED,
                    source=SOURCE, status_source="own", origin=ORIGIN,
                )


def extract(conn, dirs):
    yield from inherit(SOURCE)
    f = Path(dirs["oracle"]) / "oval.xml"
    if f.exists():
        yield from _oval_rows(f)
