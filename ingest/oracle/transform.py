"""Parse Oracle Linux OVAL XML → upsert_lve_record format."""
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator, Optional

from ingest.purl import distro_purl

_EARLIER_RE = re.compile(r"^(.+?)\s+is earlier than\s+(.+)$")
_PLATFORM_RE = re.compile(r"Oracle Linux\s+(\d+)")
_EPOCH_RE    = re.compile(r"^\d+:")

_SEVERITY_MAP = {
    "Critical":  "critical",
    "Important": "high",
    "Moderate":  "medium",
    "Low":       "low",
}


def _tag(elem) -> str:
    t = elem.tag
    return t.split("}")[-1] if "}" in t else t


def _find(parent, local: str):
    return next((c for c in parent if _tag(c) == local), None)


def _findall(parent, local: str) -> list:
    return [c for c in parent if _tag(c) == local]


def _walk_criteria(elem, pkgs: list) -> None:
    if _tag(elem) == "criterion":
        comment = elem.get("comment", "")
        m = _EARLIER_RE.match(comment)
        if m and "signed with" not in comment:
            name = m.group(1).strip()
            ver  = _EPOCH_RE.sub("", m.group(2).strip())
            pkgs.append((name, ver))
    for child in elem:
        _walk_criteria(child, pkgs)


def _parse_cvss3(raw: str) -> Optional[dict]:
    """'7.1/CVSS:3.1/AV:N/...' → {score, vector, version}."""
    if not raw:
        return None
    slash = raw.find("/")
    if slash == -1:
        return None
    try:
        score = float(raw[:slash])
    except ValueError:
        return None
    vector  = raw[slash + 1:]
    version = "3.1" if "CVSS:3.1" in vector else "3.0"
    return {"score": score, "vector": vector, "version": version}


def _transform_definition(elem) -> list:
    meta = _find(elem, "metadata")
    if meta is None:
        return []

    # ELSA ID + title
    title_elem = _find(meta, "title")
    title   = (title_elem.text or "").strip() if title_elem is not None else ""
    elsa_id = title.split(":")[0].strip() if ":" in title else None

    # CVE IDs
    cve_ids = [
        r.get("ref_id", "")
        for r in _findall(meta, "reference")
        if r.get("source") == "CVE" and r.get("ref_id", "").startswith("CVE-")
    ]
    if not cve_ids:
        return []

    # Affected OL versions
    affected    = _find(meta, "affected")
    ol_versions = []
    if affected is not None:
        for p in _findall(affected, "platform"):
            m = _PLATFORM_RE.search(p.text or "")
            if m:
                ol_versions.append(m.group(1))
    if not ol_versions:
        return []

    # Advisory block: severity, issued date, per-CVE CVSS
    advisory = _find(meta, "advisory")
    severity:   Optional[str] = None
    published:  Optional[str] = None
    cvss_per_cve: dict = {}

    if advisory is not None:
        sev = _find(advisory, "severity")
        if sev is not None:
            severity = _SEVERITY_MAP.get((sev.text or "").strip())

        issued = _find(advisory, "issued")
        if issued is not None:
            published = issued.get("date")

        for cve_elem in _findall(advisory, "cve"):
            cid   = (cve_elem.text or "").strip()
            cvss3 = _parse_cvss3(cve_elem.get("cvss3", ""))
            if cvss3 and cid:
                cvss_per_cve[cid] = {**cvss3, "severity": severity, "source": "oracle"}

    # Description
    desc_elem   = _find(meta, "description")
    description = (desc_elem.text or "").strip() if desc_elem is not None else None

    # Packages from criteria tree
    pkgs: list[tuple[str, str]] = []
    criteria = _find(elem, "criteria")
    if criteria is not None:
        _walk_criteria(criteria, pkgs)
    if not pkgs:
        return []

    # One record per CVE
    records = []
    for cve_id in cve_ids:
        packages = []
        seen: set = set()
        for pkg_name, fix_ver in pkgs:
            for ol_ver in ol_versions:
                key = (pkg_name, ol_ver)
                if key in seen:
                    continue
                seen.add(key)
                packages.append({
                    "name":              pkg_name,
                    "purl":              distro_purl("rpm", "oracle", pkg_name, f"ol{ol_ver}"),
                    "affected_state":    "affected",
                    "remediation_state": "fixed",
                    "status_raw":        "fixed",
                    "source":            "oracle",
                    "advisory":    elsa_id,
                    "vendor_data": {"cpe": f"cpe:2.3:o:oracle:linux:{ol_ver}:*:*:*:*:*:*:*"},
                    "severity":    severity,
                    "ranges":      [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fix_ver}]}],
                })

        if not packages:
            continue

        records.append({
            "aliases":      [cve_id] + ([elsa_id] if elsa_id else []),
            "cve":          {"cve_id": cve_id},
            "titles":       [{"value": title, "source": "oracle", "advisory": elsa_id}] if title else [],
            "descriptions": [{"value": description, "source": "oracle", "advisory": elsa_id}] if description else [],
            "cvss":         [cvss_per_cve[cve_id]] if cve_id in cvss_per_cve else [],
            "cwes":         [],
            "references":   [{"url": f"https://linux.oracle.com/errata/{elsa_id}.html",
                               "type": "advisory", "source": "oracle", "advisory": elsa_id}] if elsa_id else [],
            "advisories":   [{"@id":       elsa_id,
                               "source":    "oracle",
                               "url":       f"https://linux.oracle.com/errata/{elsa_id}.html",
                               "published": published}] if elsa_id else [],
            "upstream":     [],
            "packages":     packages,
            "exploits":     [],
            "notices":      [],
            "history":      ([{"date":   published,
                               "event":  "advisory_added",
                               "source": "oracle",
                               "detail": elsa_id}]
                             if elsa_id and published else []),
        })

    return records


def parse_oval(xml_path: Path) -> Iterator[dict]:
    """Yield one upsert_lve_record dict per CVE found in the OVAL XML."""
    for _event, elem in ET.iterparse(str(xml_path), events=("end",)):
        if _tag(elem) == "definition" and elem.get("class") == "patch":
            yield from _transform_definition(elem)
            elem.clear()
