"""Transform AlmaLinux errata.json → upsert_lve_record dicts."""
import datetime
from typing import Iterator

from ingest.purl import distro_purl

_SEVERITY = {"Critical": "critical", "Important": "high", "Moderate": "medium", "Low": "low"}

_REF_TYPE = {"bugzilla": "report", "rhsa": "advisory", "self": "advisory"}


def _ts(issued) -> str | None:
    if isinstance(issued, dict):
        ts_ms = issued.get("$date")
        if ts_ms:
            return datetime.datetime.utcfromtimestamp(ts_ms / 1000).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(issued, str) and issued:
        return issued[:10]
    return None


def transform_advisories(data: list, major: str) -> Iterator[dict]:
    """Yield one upsert_lve_record per CVE from AlmaLinux errata list for one major release."""
    by_cve: dict[tuple, dict] = {}

    for adv in data:
        if adv.get("type") != "security":
            continue

        adv_id    = adv.get("updateinfo_id", "")
        severity  = _SEVERITY.get(adv.get("severity", ""))
        title     = (adv.get("title") or "").strip()
        desc      = (adv.get("description") or "").strip()
        published = _ts(adv.get("issued_date"))
        updated   = _ts(adv.get("updated_date"))

        cve_ids = [ref["id"] for ref in (adv.get("references") or [])
                   if ref.get("type") == "cve" and ref.get("id", "").startswith("CVE-")]
        if not cve_ids:
            continue

        # References for this advisory (skip cve-type — those go into aliases)
        adv_refs = []
        seen_ref_urls: set = set()
        for ref in (adv.get("references") or []):
            rtype = _REF_TYPE.get(ref.get("type", ""))
            url   = ref.get("href", "")
            if not rtype or not url or url in seen_ref_urls:
                continue
            seen_ref_urls.add(url)
            adv_refs.append({"url": url, "type": rtype, "source": "almalinux", "advisory": adv_id})

        # Packages: deduplicate by (name, version, release) — skip per-arch dupes
        seen_pkgs: set = set()
        packages: list = []
        pkglist  = adv.get("pkglist") or {}
        raw_pkgs = pkglist.get("packages") if isinstance(pkglist, dict) else []

        for pkg in (raw_pkgs or []):
            name    = pkg.get("name", "")
            version = pkg.get("version", "")
            release = pkg.get("release", "")
            epoch   = str(pkg.get("epoch", "0"))
            if not name or not version:
                continue
            key = (name, version, release)
            if key in seen_pkgs:
                continue
            seen_pkgs.add(key)

            fix_ver = f"{version}-{release}" if release else version
            if epoch and epoch != "0":
                fix_ver = f"{epoch}:{fix_ver}"

            packages.append({
                "name":              name,
                "purl":              distro_purl("rpm", "almalinux", name, f"almalinux-{major}"),
                "affected_state":    "affected",
                "remediation_state": "fixed",
                "status_raw":        "fixed",
                "source":            "almalinux",
                "advisory":    adv_id,
                "vendor_data": {"cpe": f"cpe:2.3:o:almalinux:almalinux:{major}:*:*:*:*:*:*:*"},
                "severity":    severity,
                "ranges":      [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fix_ver}]}],
            })

        if not packages:
            continue

        adv_obj = {
            "id":        adv_id,
            "title":     title,
            "desc":      desc,
            "severity":  severity,
            "published": published,
            "updated":   updated,
            "refs":      adv_refs,
        }

        for cve_id in cve_ids:
            k = (cve_id, major)
            if k not in by_cve:
                by_cve[k] = {
                    "pkg_map":    {p["purl"]: p for p in packages},
                    "advisories": [adv_obj],
                }
            else:
                for p in packages:
                    existing = by_cve[k]["pkg_map"].get(p["purl"])
                    if existing is None:
                        by_cve[k]["pkg_map"][p["purl"]] = p
                    elif (p.get("advisory") or "") > (existing.get("advisory") or ""):
                        # Later advisory (higher ALSA ID) wins — more recent respin
                        by_cve[k]["pkg_map"][p["purl"]] = p
                if adv_id not in {a["id"] for a in by_cve[k]["advisories"]}:
                    by_cve[k]["advisories"].append(adv_obj)

    for (cve_id, major), info in by_cve.items():
        adv_list = info["advisories"]
        primary  = adv_list[0] if adv_list else {}

        # titles[] — one per source (descriptions for same CVE are usually identical)
        titles = ([{"value": primary["title"], "source": "almalinux",
                    "advisory": primary["id"]}]
                  if primary.get("title") else [])

        # descriptions[] — one per source
        descriptions = ([{"value": primary["desc"], "source": "almalinux",
                          "advisory": primary["id"]}]
                        if primary.get("desc") else [])

        # references[] — all refs from all advisories, deduped by URL
        seen_urls: set = set()
        references = []
        for a in adv_list:
            for ref in a["refs"]:
                if ref["url"] not in seen_urls:
                    seen_urls.add(ref["url"])
                    references.append(ref)

        # advisories[]
        advisories = [
            {
                "@id":       a["id"],
                "source":    "almalinux",
                "url":       f"https://errata.almalinux.org/{major}/{a['id'].replace(':', '-')}.html",
                "published": a["published"],
                "updated":   a["updated"],
            }
            for a in adv_list
        ]

        # history[] — vendor-native timestamps per advisory
        history = []
        for a in adv_list:
            if a["published"]:
                history.append({
                    "date":   a["published"],
                    "event":  "advisory_added",
                    "source": "almalinux",
                    "detail": a["id"],
                })
            if a["updated"] and a["updated"] != a["published"]:
                history.append({
                    "date":   a["updated"],
                    "event":  "advisory_updated",
                    "source": "almalinux",
                    "detail": a["id"],
                })

        yield {
            "aliases":      [cve_id] + [a["id"] for a in adv_list],
            "cve":          {"cve_id": cve_id},
            "titles":       titles,
            "descriptions": descriptions,
            "cvss":         [],
            "cwes":         [],
            "references":   references,
            "advisories":   advisories,
            "upstream":     [],
            "packages":     list(info["pkg_map"].values()),
            "exploits":     [],
            "notices":      [],
            "history":      history,
        }
