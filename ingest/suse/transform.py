"""Transform SUSE CSAF VEX and Advisory documents → upsert_lve_record format."""
import re
from typing import Optional
from ingest.mapping import CSAF_REM_STATES
from ingest.purl import distro_purl

_IMPACT_SUMMARY_RE = re.compile(r"Impact Summary:\s*(.+?)(?:\n\n|\Z)", re.DOTALL)

_SEVERITY_MAP = {
    "critical":  "critical",
    "important": "high",
    "moderate":  "medium",
    "low":       "low",
}

_CVSS_KEYS = ("cvss_v31", "cvss_v30", "cvss_v3", "cvss_v2")
_CVSS_VER  = {"cvss_v31": "3.1", "cvss_v30": "3.0", "cvss_v3": "3.1", "cvss_v2": "2.0"}


def _build_platform_cpe_map(branches: list) -> dict:
    """Walk product_tree branches, return {platform_product_id → cpe} for product_name entries."""
    result = {}
    for b in branches:
        if b.get("category") == "product_name":
            prod = b.get("product", {})
            pid  = prod.get("product_id", "")
            cpe  = prod.get("product_identification_helper", {}).get("cpe", "") or ""
            if pid:
                result[pid] = cpe
        if "branches" in b:
            result.update(_build_platform_cpe_map(b["branches"]))
    return result


def _distro_from_cpe(cpe: str) -> Optional[str]:
    """cpe:/o:suse:sles:15:sp5 → 'sles-15-sp5'"""
    if not cpe.startswith("cpe:/o:suse:"):
        return None
    parts = [p for p in cpe[len("cpe:/o:suse:"):].split(":") if p and p != "*"]
    return "-".join(parts) if parts else None


def _rpm_purl(name: str, cpe: str) -> str:
    return distro_purl("rpm", "suse", name, _distro_from_cpe(cpe))


def _split_pkg(pkg_str: str) -> tuple:
    """'openssl-3-3.1.4-150600.5.53.1' → ('openssl-3', '3.1.4-150600.5.53.1').
    Splits at the first '-' whose right side looks like a version (digit + dot).
    Plain digits like '3', '32bit', '64' are part of the package name, not the version."""
    parts = pkg_str.split("-")
    for i, part in enumerate(parts):
        if i > 0 and part and part[0].isdigit() and "." in part:
            return "-".join(parts[:i]), "-".join(parts[i:])
    return pkg_str, None


def _split_compound(pid: str) -> Optional[tuple]:
    """'SUSE Linux Enterprise Server 16.0:liblzma5-5.8.1' → (platform, pkg_str)."""
    colon = pid.find(":")
    if colon < 0:
        return None
    return pid[:colon], pid[colon + 1:]


def _pkg_from_compound(pid: str, platform_cpe_map: dict) -> Optional[tuple]:
    """Split compound id, return (name, version, cpe) or None if platform unknown."""
    split = _split_compound(pid)
    if not split:
        return None
    platform, pkg_str = split
    cpe = platform_cpe_map.get(platform)
    if cpe is None:
        return None
    name, version = _split_pkg(pkg_str)
    return name, version, cpe


def _ref_type(ref: dict) -> str:
    url = ref.get("url", "")
    cat = ref.get("category", "")
    if cat == "self":
        return "advisory"
    if "bugzilla" in url:
        return "report"
    if "github.com" in url and any(s in url for s in ("/blob/", "/commit/", "/pull/", "/patch")):
        return "patch"
    if "github.com" in url and "/security/advisories/" in url:
        return "advisory"
    return "web"


def transform(data: dict, adv_map: dict | None = None) -> Optional[dict]:
    """Transform one SUSE CSAF VEX CVE JSON → upsert_lve_record dict, or None if no packages."""
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    vuln   = vulns[0]
    cve_id = (vuln.get("cve") or "").upper()
    if not cve_id:
        return None

    adv_map_entry: dict[str, list[str]] = (adv_map or {}).get(cve_id, {})
    adv_ids: list[str] = list(adv_map_entry.keys())
    platform_to_adv: dict[str, str] = {
        platform: adv_id
        for adv_id, platforms in adv_map_entry.items()
        for platform in platforms
    }

    platform_cpe_map = _build_platform_cpe_map(
        data.get("product_tree", {}).get("branches", [])
    )

    doc          = data.get("document", {})
    tracking     = doc.get("tracking", {})
    severity_raw = (doc.get("aggregate_severity") or {}).get("text", "")
    severity     = _SEVERITY_MAP.get(severity_raw.lower()) if severity_raw else None

    # Description + Impact (embedded in general note as "Impact Summary:" paragraph)
    description = None
    impact_text = None
    for note in (vuln.get("notes") or []):
        cat  = note.get("category", "")
        text = (note.get("text") or "").strip()
        if cat in ("description", "general") and not description and text:
            description = text
            m = _IMPACT_SUMMARY_RE.search(text)
            if m:
                impact_text = m.group(1).strip()

    # CVSS
    cvss_list = []
    seen_cvss = set()
    for score_entry in (vuln.get("scores") or []):
        for key in _CVSS_KEYS:
            if key not in score_entry:
                continue
            cv    = score_entry[key]
            score = cv.get("baseScore")
            vec   = cv.get("vectorString")
            if score is None or not vec:   # score 0.0 is valid; vector is required (NOT NULL)
                break
            k = (str(score), vec)
            if k not in seen_cvss:
                seen_cvss.add(k)
                base_sev = cv.get("baseSeverity", "")
                cvss_list.append({
                    "version":  _CVSS_VER.get(key, "3.1"),
                    "score":    float(score),
                    "vector":   vec,
                    "severity": base_sev.lower() if base_sev and base_sev.lower() in ("critical","high","medium","low","informational","none") else None,
                    "source":   "suse",
                    "advisory": None,
                })
            break

    # References
    refs = []
    seen_ref_urls: set = set()
    for r in (vuln.get("references") or []):
        url = r.get("url", "")
        if not url or not url.startswith("http") or url in seen_ref_urls:
            continue
        seen_ref_urls.add(url)
        refs.append({"url": url, "type": _ref_type(r), "source": "suse", "advisory": None})

    packages = []
    seen     = set()
    ps       = vuln.get("product_status", {})

    def _add_fixed(pid: str):
        r = _pkg_from_compound(pid, platform_cpe_map)
        if not r:
            return
        name, version, cpe = r
        key = (name, cpe)
        if key in seen:
            return
        seen.add(key)
        platform = _split_compound(pid)[0] if _split_compound(pid) else None
        packages.append({
            "name":              name,
            "purl":              _rpm_purl(name, cpe),
            "affected_state":    "affected",
            "remediation_state": "fixed",
            "status_raw":        "fixed",
            "source":            "suse",
            "advisory":          platform_to_adv.get(platform) if platform else None,
            "severity":    severity,
            "vendor_data": {"cpe": cpe},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": version}]}]
                      if version else None,
        })

    # vendor_fix remediations → fixed
    for rem in (vuln.get("remediations") or []):
        if rem.get("category") != "vendor_fix":
            continue
        for pid in (rem.get("product_ids") or []):
            _add_fixed(pid)

    # recommended → fixed
    for pid in (ps.get("recommended") or []):
        _add_fixed(pid)

    # first_fixed → fixed
    for pid in (ps.get("first_fixed") or []):
        _add_fixed(pid)

    # known_affected → states from remediation category
    pid_rem_states: dict[str, tuple[str, str, str]] = {}
    for rem in (vuln.get("remediations") or []):
        cat    = rem.get("category", "")
        states = CSAF_REM_STATES.get(cat)
        if not states:
            continue
        for pid in (rem.get("product_ids") or []):
            if pid not in pid_rem_states:
                pid_rem_states[pid] = (states[0], states[1], cat)

    for pid in (ps.get("known_affected") or []):
        r = _pkg_from_compound(pid, platform_cpe_map)
        if not r:
            continue
        name, _, cpe = r
        key = (name, cpe)
        if key in seen:
            continue
        seen.add(key)
        aff, rem_st, raw = pid_rem_states.get(pid, ("affected", "pending", "known_affected"))
        packages.append({
            "name":              name,
            "purl":              _rpm_purl(name, cpe),
            "affected_state":    aff,
            "remediation_state": rem_st,
            "status_raw":        raw,
            "source":            "suse",
            "advisory":          None,
            "severity":          severity,
            "vendor_data":       {"cpe": cpe},
            "ranges":            None,
        })

    # under_investigation → unknown
    for pid in (ps.get("under_investigation") or []):
        r = _pkg_from_compound(pid, platform_cpe_map)
        if not r:
            continue
        name, _, cpe = r
        key = (name, cpe)
        if key in seen:
            continue
        seen.add(key)
        packages.append({
            "name":              name,
            "purl":              _rpm_purl(name, cpe),
            "affected_state":    "unknown",
            "remediation_state": "unknown",
            "status_raw":        "under_investigation",
            "source":            "suse",
            "advisory":          None,
            "severity":          severity,
            "vendor_data":       {"cpe": cpe},
            "ranges":            None,
        })

    if not packages:
        return None

    def _adv_url(aid: str) -> str:
        slug = aid.lower()
        if ":" in slug:
            prefix, rest = slug.split(":", 1)
            slug = prefix + rest
        return f"https://www.suse.com/support/update/announcement/{slug}/"

    advisories = [
        {"@id": aid, "source": "suse", "url": _adv_url(aid)}
        for aid in adv_ids
    ]

    history = []
    for rev in (tracking.get("revision_history") or []):
        rev_date = rev.get("date")
        rev_num  = rev.get("number", "")
        if not rev_date:
            continue
        history.append({
            "date":   rev_date,
            "event":  "vex_published" if rev_num == "1" else "vex_updated",
            "source": "suse",
            "detail": f"revision {rev_num}: {rev.get('summary', '')}",
        })

    vex_ref = f"csaf_vex:{cve_id}"

    return {
        "aliases":      [cve_id] + adv_ids,
        "cve":          {"cve_id": cve_id},
        "titles":       [],  # SUSE document.title always "SUSE CVE <CVE-ID>", not useful
        "descriptions": ([{"value": description, "source": "suse", "advisory": vex_ref}]
                         if description else []),
        "cvss":         cvss_list,
        "cwes":         [],
        "references":   refs,
        "advisories":   advisories,
        "upstream":     [],
        "packages":     packages,
        "mitigations":  [],
        "impacts":      ([{"value": impact_text, "source": "suse", "advisory": vex_ref}]
                         if impact_text else []),
        "exploits":     [],
        "notices":      [],
        "history":      history,
    }


def transform_advisory(data: dict) -> list[dict]:
    """Transform one SUSE CSAF Advisory JSON → list of partial records (one per CVE)."""
    doc      = data.get("document", {})
    tracking = doc.get("tracking", {})
    adv_id   = tracking.get("id", "")
    if not adv_id:
        return []

    published = tracking.get("initial_release_date")
    updated   = tracking.get("current_release_date")
    title     = doc.get("title", "").strip()

    history = []
    for rev in (tracking.get("revision_history") or []):
        rev_date = rev.get("date")
        rev_num  = rev.get("number", "")
        if not rev_date:
            continue
        history.append({
            "date":   rev_date,
            "event":  "advisory_added" if rev_num == "1" else "advisory_updated",
            "source": "suse",
            "detail": f"{adv_id} revision {rev_num}: {rev.get('summary', '')}",
        })

    records = []
    for vuln in (data.get("vulnerabilities") or []):
        cve_id = (vuln.get("cve") or "").upper()
        if not cve_id:
            continue
        records.append({
            "cve_id":    cve_id,
            "adv_id":    adv_id,
            "published": published,
            "updated":   updated,
            "title":     title or None,
            "history":   history,
        })
    return records
