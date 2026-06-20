"""Transform RedHat CSAF VEX and Advisory documents → upsert_lve_record format."""
import re
from typing import Optional
from ingest.utils import walk_branches
from ingest.mapping import CSAF_REM_STATES, VEX_JUSTIFICATIONS

_SEVERITY_MAP = {
    "critical":  "critical",
    "important": "high",
    "moderate":  "medium",
    "low":       "low",
}

_ALL_ARCHES = {".x86_64", ".aarch64", ".noarch", ".i686", ".s390x", ".ppc64le", ".ppc64", ".ppc", ".src"}
_CVSS_KEYS  = ("cvss_v31", "cvss_v30", "cvss_v3", "cvss_v2")
_CVSS_VER   = {"cvss_v31": "3.1", "cvss_v30": "3.0", "cvss_v3": "3.1", "cvss_v2": "2.0"}

_CPE22_VER_RE = re.compile(r":(\d+(?:\.\d+)?)(?:[.:]|$)")
_NVR_RE       = re.compile(r"^(.+?)-(\d+):(.+)$")


def _el_distro(cpe22: str) -> Optional[str]:
    """Return 'major.minor' for EUS/AUS/TUS CPEs, 'major' for base stream."""
    m = _CPE22_VER_RE.search(cpe22)
    return m.group(1) if m else None


def _rpm_purl(name: str, cpe22: str) -> str:
    ver  = _el_distro(cpe22)
    purl = f"pkg:rpm/redhat/{name}"
    if ver:
        purl += f"?distro=el{ver}"
    return purl


def _parse_nvr_arch(nvr_arch: str) -> Optional[tuple[str, str]]:
    """'PackageKit-0:1.1.10-2.el7.i686' → (name, '0:1.1.10-2.el7') or None for .src."""
    for arch in _ALL_ARCHES:
        if nvr_arch.endswith(arch):
            if arch == ".src":
                return None
            nvr = nvr_arch[: -len(arch)]
            m   = _NVR_RE.match(nvr)
            if not m:
                return None
            return m.group(1), f"{m.group(2)}:{m.group(3)}"
    # No arch suffix — try matching NVR anyway
    m = _NVR_RE.match(nvr_arch)
    if m:
        return m.group(1), f"{m.group(2)}:{m.group(3)}"
    return None


def _split_compound(pid: str) -> Optional[tuple[str, str]]:
    """'7Server-ELS:PackageKit-0:...' → (platform, rest). Finds the FIRST colon."""
    colon = pid.find(":")
    if colon < 0:
        return None
    return pid[:colon], pid[colon + 1:]


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
    if "GHSA-" in url:
        return "advisory"
    return "web"


def transform(data: dict) -> Optional[dict]:
    """Transform one CSAF VEX CVE JSON → upsert_lve_record dict, or None if no packages."""
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    # product_id → (cpe23, cpe22, display_name)
    platform_map: dict = {}
    walk_branches(data.get("product_tree", {}).get("branches", []), platform_map)

    doc          = data.get("document", {})
    tracking     = doc.get("tracking", {})
    severity_raw = (doc.get("aggregate_severity") or {}).get("text", "")
    severity     = _SEVERITY_MAP.get(severity_raw.lower()) if severity_raw else None

    vuln   = vulns[0]  # VEX files are one-CVE-per-file
    cve_id = (vuln.get("cve") or "").upper()
    if not cve_id:
        return None

    # Notes
    description = statement = None
    for note in (vuln.get("notes") or []):
        cat  = note.get("category", "")
        text = (note.get("text") or "").strip()
        if cat in ("description", "general") and not description and text:
            description = text
        elif cat == "other" and not statement and text:
            statement = text

    # Mitigations — workaround/mitigation remediations (prose, CVE-wide)
    mitigations: list[dict] = []
    seen_mitig: set = set()
    for rem in (vuln.get("remediations") or []):
        if rem.get("category") not in ("workaround", "mitigation"):
            continue
        text = (rem.get("details") or "").strip()
        if not text or text in seen_mitig:
            continue
        seen_mitig.add(text)
        mitigations.append({"value": text, "source": "redhat", "advisory": f"csaf_vex:{cve_id}", "purls": None})

    # Impacts — vendor statement note (most informative) or threats[impact] rating
    impacts: list[dict] = []
    vex_ref_impact = f"csaf_vex:{cve_id}"
    impact_text = statement  # "Moderate: This flaw in OpenSSL's..." — best content
    if not impact_text:
        for t in (vuln.get("threats") or []):
            if t.get("category") == "impact" and t.get("details"):
                impact_text = t["details"].strip()
                break
    if impact_text:
        impacts.append({"value": impact_text, "source": "redhat", "advisory": vex_ref_impact})

    # CWE
    cwes = []
    cwe  = vuln.get("cwe") or {}
    if isinstance(cwe, dict) and cwe.get("id"):
        cwes = [{"id": cwe["id"], "name": cwe.get("name"), "source": "redhat", "advisory": None}]

    # CVSS
    cvss_list  = []
    seen_cvss: set = set()
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
                    "severity": base_sev.lower() if base_sev and base_sev.lower() in ("critical", "high", "medium", "low", "informational", "none") else None,
                    "source":   "redhat",
                    "advisory": None,
                })
            break

    # References — with proper type mapping
    refs = []
    seen_ref_urls: set = set()
    for r in (vuln.get("references") or []):
        url = r.get("url", "")
        if not url or not url.startswith("http") or url in seen_ref_urls:
            continue
        seen_ref_urls.add(url)
        refs.append({"url": url, "type": _ref_type(r), "source": "redhat", "advisory": None})

    packages: list[dict] = []
    pkg_idx:  dict[tuple, int] = {}  # (name, cpe22) → index in packages

    # ── vendor_fix → fixed ───────────────────────────────────────────────────
    # rhsa_map: {rhsa_id: published_date}
    rhsa_map: dict[str, Optional[str]] = {}

    for rem in (vuln.get("remediations") or []):
        if rem.get("category") != "vendor_fix":
            continue

        rem_url  = rem.get("url", "")
        rhsa_id: str | None = None
        if "/errata/RH" in rem_url:
            rhsa_id = rem_url.rsplit("/", 1)[-1]
            if rhsa_id not in rhsa_map:
                rhsa_map[rhsa_id] = rem.get("date")

        for pid in (rem.get("product_ids") or []):
            split = _split_compound(pid)
            if not split:
                continue
            platform, nvr_arch = split
            entry = platform_map.get(platform)
            if not entry:
                continue
            _, cpe22, _ = entry
            parsed = _parse_nvr_arch(nvr_arch)
            if not parsed:
                continue
            name, version = parsed
            key = (name, cpe22)
            pkg = {
                "name":              name,
                "purl":              _rpm_purl(name, cpe22),
                "affected_state":    "affected",
                "remediation_state": "fixed",
                "status_raw":        "fixed",
                "source":            "redhat",
                "advisory":          rhsa_id,
                "severity":          severity,
                "vendor_data":       {"cpe": cpe22},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": version}]}],
            }
            if key in pkg_idx:
                # Multiple RHSAs for the same (package, platform) — keep the later one.
                # Higher RHSA ID = more recent respin within the same year.
                existing_rhsa = packages[pkg_idx[key]].get("advisory") or ""
                if (rhsa_id or "") > existing_rhsa:
                    packages[pkg_idx[key]] = pkg
            else:
                pkg_idx[key] = len(packages)
                packages.append(pkg)

    seen: set = set(pkg_idx.keys())

    # ── VEX justification index from flags[] ─────────────────────────────────
    pid_justification: dict[str, str] = {}
    for flag in (vuln.get("flags") or []):
        label = flag.get("label", "")
        if label in VEX_JUSTIFICATIONS:
            for fpid in (flag.get("product_ids") or []):
                pid_justification[fpid] = label

    # ── known_not_affected → not_affected ────────────────────────────────────
    ps = vuln.get("product_status", {})
    for pid in (ps.get("known_not_affected") or []):
        split = _split_compound(pid)
        if not split:
            continue
        platform, pkg_name = split
        entry = platform_map.get(platform)
        if not entry:
            continue
        _, cpe22, _ = entry
        key = (pkg_name, cpe22)
        if key in seen:
            continue
        seen.add(key)
        packages.append({
            "name":              pkg_name,
            "purl":              _rpm_purl(pkg_name, cpe22),
            "affected_state":    "not_affected",
            "remediation_state": "unknown",
            "status_raw":        "known_not_affected",
            "vex_justification": pid_justification.get(pid),
            "source":            "redhat",
            "advisory":          None,
            "severity":          severity,
            "vendor_data":       {"cpe": cpe22},
            "ranges":            None,
        })

    # ── known_affected + remediation category → states ───────────────────────
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
        split = _split_compound(pid)
        if not split:
            continue
        platform, pkg_part = split
        entry = platform_map.get(platform)
        if not entry:
            continue
        _, cpe22, _ = entry
        parsed   = _parse_nvr_arch(pkg_part)
        pkg_name = parsed[0] if parsed else pkg_part
        key = (pkg_name, cpe22)
        if key in seen:
            continue
        seen.add(key)
        aff, rem_st, raw = pid_rem_states.get(pid, ("affected", "pending", "known_affected"))
        packages.append({
            "name":              pkg_name,
            "purl":              _rpm_purl(pkg_name, cpe22),
            "affected_state":    aff,
            "remediation_state": rem_st,
            "status_raw":        raw,
            "source":            "redhat",
            "advisory":          None,
            "severity":          severity,
            "vendor_data":       {"cpe": cpe22},
            "ranges":            None,
        })

    # ── under_investigation → unknown ────────────────────────────────────────
    for pid in (ps.get("under_investigation") or []):
        split = _split_compound(pid)
        if not split:
            continue
        platform, pkg_part = split
        entry = platform_map.get(platform)
        if not entry:
            continue
        _, cpe22, _ = entry
        parsed   = _parse_nvr_arch(pkg_part)
        pkg_name = parsed[0] if parsed else pkg_part
        key = (pkg_name, cpe22)
        if key in seen:
            continue
        seen.add(key)
        packages.append({
            "name":              pkg_name,
            "purl":              _rpm_purl(pkg_name, cpe22),
            "affected_state":    "unknown",
            "remediation_state": "unknown",
            "status_raw":        "under_investigation",
            "source":            "redhat",
            "advisory":          None,
            "severity":          severity,
            "vendor_data":       {"cpe": cpe22},
            "ranges":            None,
        })

    if not packages:
        return None

    advisories = [
        {
            "@id":       rid,
            "source":    "redhat",
            "url":       f"https://access.redhat.com/errata/{rid}",
            "published": rhsa_map[rid],
        }
        for rid in sorted(rhsa_map.keys())
    ]

    # history — per RHSA advisory_added + CVE document revision history
    history = []
    for rid, pub in sorted(rhsa_map.items(), key=lambda x: x[1] or ""):
        if pub:
            history.append({
                "date":   pub,
                "event":  "advisory_added",
                "source": "redhat",
                "detail": rid,
            })
    for rev in (tracking.get("revision_history") or []):
        rev_date = rev.get("date")
        rev_num  = rev.get("number", "")
        if not rev_date:
            continue
        history.append({
            "date":   rev_date,
            "event":  "vex_published" if rev_num == "1" else "vex_updated",
            "source": "redhat",
            "detail": f"revision {rev_num}: {rev.get('summary', '')}",
        })

    vex_ref = f"csaf_vex:{cve_id}"

    return {
        "aliases":      [cve_id] + sorted(rhsa_map.keys()),
        "cve":          {"cve_id": cve_id},
        "titles":       ([{"value": vuln["title"], "source": "redhat", "advisory": vex_ref}]
                         if vuln.get("title") else []),
        "descriptions": ([{"value": description, "source": "redhat", "advisory": vex_ref}]
                         if description else []),
        "cvss":         cvss_list,
        "cwes":         cwes,
        "references":   refs,
        "advisories":   advisories,
        "upstream":     [],
        "packages":     packages,
        "mitigations":  mitigations,
        "impacts":      impacts,
        "exploits":     [],
        "notices":      [],
        "history":      history,
    }


def transform_advisory(data: dict) -> list[dict]:
    """Transform one CSAF Advisory JSON → list of partial records (one per CVE in the advisory)."""
    doc      = data.get("document", {})
    tracking = doc.get("tracking", {})
    rhsa_id  = tracking.get("id", "").upper()
    if not rhsa_id:
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
            "source": "redhat",
            "detail": f"{rhsa_id} revision {rev_num}: {rev.get('summary', '')}",
        })

    reboot_required = any(
        (vuln.get("remediations") or [{}])[0].get("restart_required", {}).get("category") == "machine"
        for vuln in (data.get("vulnerabilities") or [])
        if (vuln.get("remediations") or [])
    )

    records = []
    for vuln in (data.get("vulnerabilities") or []):
        cve_id = (vuln.get("cve") or "").upper()
        if not cve_id:
            continue
        records.append({
            "cve_id":          cve_id,
            "rhsa_id":         rhsa_id,
            "published":       published,
            "updated":         updated,
            "title":           title or None,
            "history":         history,
            "reboot_required": reboot_required,
        })
    return records
