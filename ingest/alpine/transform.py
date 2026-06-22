"""Transform Alpine secdb JSON → upsert_lve_record dicts."""
import re
from typing import Iterator

from ingest.purl import distro_purl

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def _cpe(version_str: str) -> str:
    ver = version_str.lstrip("v")  # "v3.20" → "3.20", "edge" stays "edge"
    return f"cpe:2.3:o:alpinelinux:alpine_linux:{ver}:*:*:*:*:*:*:*"


def transform_file(data: dict) -> Iterator[dict]:
    """Yield one upsert_lve_record per CVE from one Alpine secdb JSON file."""
    version_str = data.get("distroversion", "")  # e.g. "v3.20"
    cpe = _cpe(version_str)

    by_cve: dict[str, list[dict]] = {}

    for pkg_entry in (data.get("packages") or []):
        pkg = pkg_entry.get("pkg", {})
        name = pkg.get("name", "")
        if not name:
            continue
        secfixes = pkg.get("secfixes") or {}

        for fix_ver, cve_list in secfixes.items():
            for raw_id in (cve_list or []):
                # CVE IDs can be space-separated in one list entry
                for cve_id in str(raw_id).split():
                    if not _CVE_RE.match(cve_id):
                        continue

                    if fix_ver == "0":
                        aff, rem_st, fix_version = "not_affected", "unknown", None
                    else:
                        aff, rem_st, fix_version = "affected", "fixed", fix_ver

                    pkg_rec = {
                        "name":              name,
                        "purl":              distro_purl("apk", "alpine", name, version_str),
                        "affected_state":    aff,
                        "remediation_state": rem_st,
                        "status_raw":        "0" if fix_ver == "0" else fix_ver,
                        "source":            "alpine",
                        "vendor_data":       {"cpe": cpe},
                        "ranges":            [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fix_version}]}]
                                             if fix_version else None,
                    }

                    by_cve.setdefault(cve_id, []).append(pkg_rec)

    for cve_id, packages in by_cve.items():
        yield {
            "aliases":      [cve_id],
            "cve":          {"cve_id": cve_id},
            "titles":       [],
            "descriptions": [],
            "cvss":         [],
            "cwes":         [],
            "references":   [],
            "advisories":   [],
            "upstream":     [],
            "packages":     packages,
            "exploits":     [],
            "notices":      [],
            "history":      [],
        }
