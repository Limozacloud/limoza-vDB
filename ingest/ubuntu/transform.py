"""Transform Ubuntu OpenVEX CVE document → upsert_lve_record format."""
from typing import Optional

# codename → (version_string, display_name)
_CODENAMES: dict[str, tuple[str, str]] = {
    "resolute": ("26.04", "Ubuntu 26.04"),
    "questing":  ("25.10", "Ubuntu 25.10"),
    "plucky":    ("25.04", "Ubuntu 25.04"),
    "noble":     ("24.04", "Ubuntu 24.04 LTS"),
    "mantic":    ("23.10", "Ubuntu 23.10"),
    "lunar":     ("23.04", "Ubuntu 23.04"),
    "kinetic":   ("22.10", "Ubuntu 22.10"),
    "jammy":     ("22.04", "Ubuntu 22.04 LTS"),
    "impish":    ("21.10", "Ubuntu 21.10"),
    "hirsute":   ("21.04", "Ubuntu 21.04"),
    "groovy":    ("20.10", "Ubuntu 20.10"),
    "focal":     ("20.04", "Ubuntu 20.04 LTS"),
    "eoan":      ("19.10", "Ubuntu 19.10"),
    "disco":     ("19.04", "Ubuntu 19.04"),
    "cosmic":    ("18.10", "Ubuntu 18.10"),
    "bionic":    ("18.04", "Ubuntu 18.04 LTS"),
    "xenial":    ("16.04", "Ubuntu 16.04 LTS"),
    "trusty":    ("14.04", "Ubuntu 14.04 LTS"),
    "precise":   ("12.04", "Ubuntu 12.04 LTS"),
}

# OpenVEX status → (affected_state, remediation_state)
_STATUS_STATES: dict[str, tuple[str, str]] = {
    "fixed":               ("affected",     "fixed"),
    "affected":            ("affected",     "pending"),
    "not_affected":        ("not_affected", "unknown"),
    "under_investigation": ("unknown",      "unknown"),
}

_UBUNTU_SEVERITY = {
    "critical":   "critical",
    "high":       "high",
    "medium":     "medium",
    "low":        "low",
    "negligible": "informational",
}


def _cpe(version: str) -> str:
    return f"cpe:2.3:o:canonical:ubuntu_linux:{version}:*:*:*:*:*:*:*"


def _parse_purl(purl: str) -> Optional[tuple]:
    """Parse pkg:deb/ubuntu/NAME@VERSION?arch=X&distro=Y.
    Returns (name, version_or_None, arch, distro_codename) or None.
    """
    if not purl.startswith("pkg:deb/ubuntu/"):
        return None
    rest = purl[len("pkg:deb/ubuntu/"):]

    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)

    name, version = (rest.split("@", 1) + [None])[:2]

    params = {}
    for kv in query.split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            params[k] = v

    arch   = params.get("arch", "")
    distro = params.get("distro", "")

    # ESM distros: "esm-infra-legacy/trusty" → "trusty"
    if "/" in distro:
        distro = distro.rsplit("/", 1)[-1]

    return name, version, arch, distro


def _deb_purl(name: str, codename: str) -> str:
    return f"pkg:deb/ubuntu/{name}?distro={codename}"


def _usn_from_aliases(aliases: list) -> Optional[str]:
    for a in aliases:
        if "ubuntu.com/security/notices/USN-" in a:
            return a.rsplit("/", 1)[-1]
    return None


def _unix_to_iso(ts) -> Optional[str]:
    """Convert Unix timestamp (float or int) to ISO 8601 string."""
    if ts is None:
        return None
    try:
        import datetime
        return datetime.datetime.fromtimestamp(
            float(ts), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def transform(cve_id: str, data: dict,
              usn_meta: dict | None = None,
              cve_to_usn: dict | None = None,
              osv_data: dict | None = None) -> Optional[dict]:
    usn_meta   = usn_meta   or {}
    cve_to_usn = cve_to_usn or {}

    statements = data.get("statements") or []
    if not statements:
        return None

    # Description + references from first statement's vulnerability block
    vuln_block  = statements[0].get("vulnerability") or {}
    description = (vuln_block.get("description") or "").strip() or None
    aliases_raw = vuln_block.get("aliases") or []

    # USN IDs: from VEX aliases + from reverse CVE→USN mapping
    usn_id_from_vex = _usn_from_aliases(aliases_raw)
    all_usn_ids = list(dict.fromkeys(
        ([usn_id_from_vex] if usn_id_from_vex else []) +
        cve_to_usn.get(cve_id, [])
    ))
    # Primary USN: from VEX if available, else first from mapping
    usn_id = all_usn_ids[0] if all_usn_ids else None

    refs   = []
    for a in aliases_raw:
        if a.startswith("http") and "nvd.nist.gov" not in a and "ubuntu.com/security/CVE" not in a:
            refs.append({"url": a, "type": "advisory" if "notices" in a else "web",
                         "source": "ubuntu", "advisory": usn_id})

    packages = []
    seen     = set()

    for stmt in statements:
        status_raw        = stmt.get("status", "")
        aff, rem_st       = _STATUS_STATES.get(status_raw, ("unknown", "unknown"))
        vex_justification = stmt.get("justification") or None
        products          = stmt.get("products") or []

        for purl_entry in products:
            purl_str = purl_entry.get("@id", "") if isinstance(purl_entry, dict) else purl_entry
            parsed = _parse_purl(purl_str)
            if not parsed:
                continue
            name, version, arch, codename = parsed

            # Only source packages to avoid per-arch duplicates
            if arch != "source":
                continue

            entry = _CODENAMES.get(codename)
            if not entry:
                continue
            ver_str, _ = entry
            cpe23      = _cpe(ver_str)

            key = (name, codename)
            if key in seen:
                continue
            seen.add(key)

            pkg: dict = {
                "name":              name,
                "purl":              _deb_purl(name, codename),
                "affected_state":    aff,
                "remediation_state": rem_st,
                "status_raw":        status_raw,
                "vex_justification": vex_justification,
                "source":            "ubuntu",
                "advisory":          usn_id,
                "vendor_data":       {"cpe": cpe23},
                "ranges":            [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": version}]}]
                                     if rem_st == "fixed" and version else None,
            }

            packages.append(pkg)

    if not packages:
        return None

    # Ubuntu severity from OSV (type: "Ubuntu", score: "medium"/"high"/etc.)
    ubuntu_severity = None
    if osv_data:
        for sev in osv_data.get("severity", []):
            if sev.get("type") == "Ubuntu":
                ubuntu_severity = _UBUNTU_SEVERITY.get(sev.get("score", "").lower())
                break
    for pkg in packages:
        pkg["severity"] = ubuntu_severity

    # Earliest statement timestamp as fallback date
    stmt_timestamps = [s.get("timestamp") for s in statements if s.get("timestamp")]
    earliest_stmt_ts = min(stmt_timestamps) if stmt_timestamps else None

    # Build advisories + history from USN metadata
    advisories = []
    history    = []
    for uid in all_usn_ids:
        meta = usn_meta.get(uid, {})
        pub  = _unix_to_iso(meta.get("timestamp")) if meta else None
        advisories.append({
            "@id":       uid,
            "source":    "ubuntu",
            "url":       f"https://ubuntu.com/security/notices/{uid}",
            "published": pub,
        })
        if pub:
            history.append({
                "date":   pub,
                "event":  "advisory_added",
                "source": "ubuntu",
                "detail": uid,
            })

    # Fallback history from statement timestamp if no USN date available
    if not history and earliest_stmt_ts:
        history.append({
            "date":   earliest_stmt_ts,
            "event":  "advisory_added",
            "source": "ubuntu",
            "detail": usn_id or cve_id,
        })

    # Title + description from primary USN
    primary_meta = usn_meta.get(usn_id, {}) if usn_id else {}
    usn_title    = primary_meta.get("title", "").strip() or None
    usn_summary  = primary_meta.get("summary", "").strip() or None

    # Prefer USN description over VEX description; keep VEX as fallback
    final_description = description or usn_summary

    return {
        "aliases":      [cve_id] + all_usn_ids,
        "cve":          {"cve_id": cve_id},
        "titles":       ([{"value": usn_title, "source": "ubuntu", "advisory": usn_id}]
                         if usn_title else []),
        "descriptions": ([{"value": final_description, "source": "ubuntu", "advisory": usn_id}]
                         if final_description else []),
        "cvss":         [],
        "cwes":         [],
        "references":   refs,
        "advisories":   advisories,
        "upstream":     [],
        "packages":     packages,
        "exploits":     [],
        "notices":      [],
        "history":      history,
    }
