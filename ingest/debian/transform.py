"""Transform Debian Security Tracker JSON → upsert_lve_record format."""
import re
from typing import Iterator, Optional

from ingest.purl import distro_purl

_ADV_HDR_RE  = re.compile(r"^\[(\d{1,2})\s+(\w{3})\s+(\d{4})\]\s+((?:DSA|DLA)-\d+-\d+)\s+(.*?)$")
_CVE_LINE_RE = re.compile(r"\{([^}]+)\}")
_REL_LINE_RE = re.compile(r"^\s+\[([^\]]+)\]")

_MONTH = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_dsa_date(day: str, mon: str, year: str) -> Optional[str]:
    m = _MONTH.get(mon)
    if not m:
        return None
    return f"{int(year):04d}-{m:02d}-{int(day):02d}T00:00:00Z"


def _adv_url(adv_id: str) -> str:
    return f"https://security-tracker.debian.org/tracker/{adv_id}"


def parse_adv_list(text: str) -> tuple[dict, dict, dict]:
    """Parse a Debian DSA/DLA list file.

    Returns:
        adv_map:    {(cve_id, codename): [adv_id, ...]} — all advisories per pair
        adv_dates:  {adv_id: iso_date}
        adv_titles: {adv_id: title_string}
    """
    adv_map:    dict[tuple, list[str]] = {}
    adv_dates:  dict[str, str]         = {}
    adv_titles: dict[str, str]         = {}
    current_adv:  Optional[str] = None
    current_date: Optional[str] = None
    current_cves: list[str]     = []

    for line in text.splitlines():
        m = _ADV_HDR_RE.match(line)
        if m:
            current_adv  = m.group(4)
            current_date = _parse_dsa_date(m.group(1), m.group(2), m.group(3))
            current_cves = []
            if current_adv:
                if current_date:
                    adv_dates[current_adv] = current_date
                title = m.group(5).strip()
                if title:
                    adv_titles[current_adv] = title
            continue

        if current_adv is None:
            continue

        cm = _CVE_LINE_RE.search(line)
        if cm and line.strip().startswith("{"):
            current_cves = [c for c in cm.group(1).split() if c.startswith("CVE-")]
            continue

        rm = _REL_LINE_RE.match(line)
        if rm and current_cves:
            codename = rm.group(1)
            for cve_id in current_cves:
                key = (cve_id, codename)
                if current_adv not in adv_map.get(key, []):
                    adv_map.setdefault(key, []).append(current_adv)

    return adv_map, adv_dates, adv_titles


# codename → (major_version, display_name)
_CODENAMES: dict[str, tuple[str, str]] = {
    "buster":   ("10", "Debian GNU/Linux 10 (buster)"),
    "bullseye": ("11", "Debian GNU/Linux 11 (bullseye)"),
    "bookworm": ("12", "Debian GNU/Linux 12 (bookworm)"),
    "trixie":   ("13", "Debian GNU/Linux 13 (trixie)"),
    "forky":    ("14", "Debian GNU/Linux 14 (forky)"),
}

_URGENCY_SEVERITY: dict[str, str] = {
    "low":    "low",
    "low**":  "low",
    "medium": "medium",
    "high":   "high",
}


def _cpe(major: str) -> str:
    return f"cpe:2.3:o:debian:debian_linux:{major}:*:*:*:*:*:*:*"


def _purl(name: str, codename: str) -> str:
    return distro_purl("deb", "debian", name, codename)


def _states(status: str, fixed_version: str) -> tuple[str, str, Optional[str]]:
    """Return (affected_state, remediation_state, fix_version)."""
    if status == "resolved":
        if fixed_version and fixed_version != "0":
            return "affected", "fixed", fixed_version
        return "not_affected", "unknown", None
    if status == "open":
        return "affected", "pending", None
    return "unknown", "unknown", None


def transform(data: dict, adv_map: dict | None = None, adv_dates: dict | None = None, adv_titles: dict | None = None) -> Iterator[dict]:
    """Yield one upsert_lve_record per CVE from the Debian tracker JSON."""
    adv_map    = adv_map    or {}
    adv_dates  = adv_dates  or {}
    adv_titles = adv_titles or {}

    by_cve: dict[str, dict] = {}

    for pkg_name, cves in data.items():
        if not isinstance(cves, dict):
            continue
        for cve_id, cve_data in cves.items():
            if not cve_id.startswith("CVE-"):
                continue
            if not isinstance(cve_data, dict):
                continue

            if cve_id not in by_cve:
                by_cve[cve_id] = {
                    "description": (cve_data.get("description") or "").strip(),
                    "packages":    [],
                    "adv_ids":     set(),
                }

            releases = cve_data.get("releases") or {}
            for codename, rel in releases.items():
                ver_info = _CODENAMES.get(codename)
                if not ver_info or not isinstance(rel, dict):
                    continue
                major, _ = ver_info
                status_raw   = rel.get("status", "")
                fixed_ver    = (rel.get("fixed_version") or "").strip()
                urgency      = rel.get("urgency", "")
                nodsa_reason = rel.get("nodsa_reason") or None

                aff, rem_st, fix_version = _states(status_raw, fixed_ver)
                severity = _URGENCY_SEVERITY.get(urgency)

                # All advisories for this (cve, codename) pair
                adv_ids_for_pkg = adv_map.get((cve_id, codename), [])
                for aid in adv_ids_for_pkg:
                    by_cve[cve_id]["adv_ids"].add(aid)

                primary_adv = adv_ids_for_pkg[0] if adv_ids_for_pkg else None

                vendor_data: dict = {"cpe": _cpe(major)}
                if nodsa_reason:
                    vendor_data["nodsa_reason"] = nodsa_reason

                pkg: dict = {
                    "name":              pkg_name,
                    "purl":              _purl(pkg_name, codename),
                    "affected_state":    aff,
                    "remediation_state": rem_st,
                    "status_raw":        status_raw,
                    "source":            "debian",
                    "vendor_data":       vendor_data,
                    "severity":          severity,
                    "ranges":            [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fix_version}]}]
                                         if fix_version else None,
                }
                if primary_adv:
                    pkg["advisory"] = primary_adv

                by_cve[cve_id]["packages"].append(pkg)

    for cve_id, info in by_cve.items():
        packages = info["packages"]
        if not packages:
            continue

        description = info["description"]
        # Sort advisories: earliest first (by date, then ID)
        adv_ids = sorted(
            info["adv_ids"],
            key=lambda aid: (adv_dates.get(aid) or "9999", aid),
        )
        advisories = [{"@id": aid, "source": "debian", "url": _adv_url(aid),
                       "published": adv_dates.get(aid)}
                      for aid in adv_ids]

        history = [
            {
                "date":   adv_dates[aid],
                "event":  "advisory_added",
                "source": "debian",
                "detail": aid,
            }
            for aid in adv_ids
            if aid in adv_dates
        ]

        # Title from primary (earliest) advisory
        primary_title = next(
            (adv_titles[aid] for aid in adv_ids if aid in adv_titles), None
        )

        yield {
            "aliases":      [cve_id] + adv_ids,
            "cve":          {"cve_id": cve_id},
            "titles":       ([{"value": primary_title, "source": "debian",
                               "advisory": adv_ids[0]}]
                             if primary_title else []),
            "descriptions": [{"value": description, "source": "debian"}] if description else [],
            "cvss":         [],
            "cwes":         [],
            "references":   [{"url": f"https://security-tracker.debian.org/tracker/{cve_id}",
                               "type": "advisory", "source": "debian"}],
            "advisories":   advisories,
            "upstream":     [],
            "packages":     packages,
            "exploits":     [],
            "notices":      [],
            "history":      history,
        }
