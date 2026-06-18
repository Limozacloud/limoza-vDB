"""Transform Rocky Linux errata: updateinfo.xml + Apollo API advisories."""
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator, Optional

_SEVERITY = {"Critical": "critical", "Important": "high", "Moderate": "medium", "Low": "low"}
_REF_TYPE  = {"bugzilla": "report", "self": "advisory"}


# ── updateinfo.xml (bulk history) ─────────────────────────────────────────────

def _tag(elem) -> str:
    t = elem.tag
    return t.split("}")[-1] if "}" in t else t


def _text(elem, child: str) -> str:
    c = elem.find(child)
    return (c.text or "").strip() if c is not None else ""


def _date(elem, child: str) -> Optional[str]:
    c = elem.find(child)
    if c is None:
        return None
    d = c.get("date", "").strip()
    if not d:
        return None
    return d.replace(" ", "T") + "Z" if "T" not in d else d


def parse_updateinfo(xml_path: Path, major: str) -> Iterator[dict]:
    """Yield one upsert_lve_record per CVE from a Rocky Linux updateinfo.xml."""
    by_cve: dict[tuple, dict] = {}

    try:
        tree = ET.parse(str(xml_path))
    except Exception as e:
        print(f"  Rocky: parse error {xml_path}: {e}")
        return

    for update in tree.getroot():
        if _tag(update) != "update" or update.get("type") != "security":
            continue

        adv_id = _text(update, "id")
        if not adv_id:
            continue

        title     = _text(update, "title")
        desc      = _text(update, "description")
        severity  = _SEVERITY.get(_text(update, "severity"))
        published = _date(update, "issued")
        updated   = _date(update, "updated")

        cve_ids: list[str] = []
        adv_refs: list[dict] = []
        seen_ref_urls: set = set()
        refs_elem = update.find("references")
        if refs_elem is not None:
            for ref in refs_elem:
                ref_type_raw = ref.get("type", "")
                rid  = ref.get("id", "")
                href = ref.get("href", "")
                if ref_type_raw == "cve":
                    if rid.startswith("CVE-") and rid not in cve_ids:
                        cve_ids.append(rid)
                    continue
                if href and href not in seen_ref_urls:
                    seen_ref_urls.add(href)
                    adv_refs.append({
                        "url":      href,
                        "type":     _REF_TYPE.get(ref_type_raw, "web"),
                        "source":   "rocky",
                        "advisory": adv_id,
                    })

        if not cve_ids:
            continue

        seen_pkg: set = set()
        packages: list = []
        pkglist = update.find("pkglist")
        if pkglist is not None:
            for coll in pkglist:
                for pkg in coll:
                    if _tag(pkg) != "package":
                        continue
                    name    = pkg.get("name", "")
                    version = pkg.get("version", "")
                    release = pkg.get("release", "")
                    arch    = pkg.get("arch", "")
                    epoch   = pkg.get("epoch", "0")
                    if not name or not version or arch == "src":
                        continue
                    key = (name, version, release)
                    if key in seen_pkg:
                        continue
                    seen_pkg.add(key)
                    fix_ver = f"{version}-{release}" if release else version
                    if epoch and epoch != "0":
                        fix_ver = f"{epoch}:{fix_ver}"
                    packages.append({
                        "name":              name,
                        "purl":              f"pkg:rpm/rocky/{name}?distro=rocky-{major}",
                        "affected_state":    "affected",
                        "remediation_state": "fixed",
                        "status_raw":        "fixed",
                        "source":            "rocky",
                        "advisory":    adv_id,
                        "vendor_data": {"cpe": f"cpe:2.3:o:rocky:rocky_linux:{major}:*:*:*:*:*:*:*"},
                        "severity":    severity,
                        "ranges":      [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fix_ver}]}],
                    })

        if not packages:
            continue

        adv_obj = {
            "id": adv_id, "title": title, "desc": desc,
            "severity": severity, "published": published, "updated": updated,
            "refs": adv_refs,
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
                        by_cve[k]["pkg_map"][p["purl"]] = p
                if adv_id not in {a["id"] for a in by_cve[k]["advisories"]}:
                    by_cve[k]["advisories"].append(adv_obj)

    for (cve_id, major), info in by_cve.items():
        adv_list = info["advisories"]
        primary  = adv_list[0] if adv_list else {}

        seen_urls: set = set()
        references: list = []
        for a in adv_list:
            for r in a.get("refs", []):
                if r["url"] not in seen_urls:
                    seen_urls.add(r["url"])
                    references.append(r)

        history: list = []
        for a in adv_list:
            if a.get("published"):
                history.append({"date": a["published"], "event": "advisory_added",
                                 "source": "rocky", "detail": a["id"]})
            if a.get("updated") and a.get("updated") != a.get("published"):
                history.append({"date": a["updated"], "event": "advisory_updated",
                                 "source": "rocky", "detail": a["id"]})

        yield {
            "aliases":      [cve_id] + [a["id"] for a in adv_list],
            "cve":          {"cve_id": cve_id},
            "titles":       ([{"value": primary["title"], "source": "rocky", "advisory": primary["id"]}]
                             if primary.get("title") else []),
            "descriptions": ([{"value": primary["desc"], "source": "rocky", "advisory": primary["id"]}]
                             if primary.get("desc") else []),
            "cvss":         [],
            "cwes":         [],
            "references":   references,
            "advisories":   [{"@id": a["id"], "source": "rocky",
                               "url": f"https://errata.rockylinux.org/{a['id']}",
                               "published": a["published"], "updated": a["updated"]}
                              for a in adv_list],
            "upstream":     [],
            "packages":     list(info["pkg_map"].values()),
            "exploits":     [],
            "notices":      [],
            "history":      history,
        }
_SKIP_ARCH = {"src", "nosrc"}


def _parse_nevra(nevra: str) -> Optional[tuple]:
    """'openssl-1:3.5.5-4.el9_8.x86_64.rpm' → (name, epoch, version, release, arch) or None."""
    s = nevra.removesuffix(".rpm")
    colon = s.find(":")
    if colon < 0:
        return None
    before = s[:colon]   # e.g. "openssl-1" or "openssl-devel-1"
    after  = s[colon+1:] # e.g. "3.5.5-4.el9_8.x86_64"

    dash = before.rfind("-")
    if dash < 0:
        return None
    name  = before[:dash]
    epoch = before[dash+1:]

    dot = after.rfind(".")
    if dot < 0:
        return None
    arch    = after[dot+1:]
    ver_rel = after[:dot]  # e.g. "3.5.5-4.el9_8"

    dash2 = ver_rel.find("-")
    if dash2 < 0:
        return None
    version = ver_rel[:dash2]
    release = ver_rel[dash2+1:]

    return name, epoch, version, release, arch


_MAJOR_RE = re.compile(r"Rocky Linux (\d+)")


def _major_from_product(product_name: str) -> Optional[str]:
    m = _MAJOR_RE.search(product_name)
    return m.group(1) if m else None


def transform_advisories(advisories: list[dict]) -> Iterator[dict]:
    """Yield one upsert_lve_record per (CVE, major_version) from Apollo advisory list."""
    by_cve: dict[tuple, dict] = {}

    for adv in advisories:
        if adv.get("kind") != "Security":
            continue

        adv_id    = adv.get("name", "")
        severity  = _SEVERITY.get(adv.get("severity", ""))
        published = adv.get("published_at", "")
        updated   = adv.get("updated_at", "")

        cve_ids = [
            c["cve"] for c in (adv.get("cves") or [])
            if c.get("cve", "").startswith("CVE-")
        ]
        if not cve_ids:
            continue

        # Packages grouped by major version
        seen_pkg: set = set()
        pkgs_by_major: dict[str, list] = {}

        for pkg in (adv.get("packages") or []):
            nevra        = pkg.get("nevra", "")
            product_name = pkg.get("product_name", "")
            major        = _major_from_product(product_name)
            if not major:
                continue

            parsed = _parse_nevra(nevra)
            if not parsed:
                continue
            name, epoch, version, release, arch = parsed
            if arch in _SKIP_ARCH:
                continue

            key = (name, version, release, major)
            if key in seen_pkg:
                continue
            seen_pkg.add(key)

            fix_ver = f"{version}-{release}"
            if epoch and epoch != "0":
                fix_ver = f"{epoch}:{fix_ver}"

            pkgs_by_major.setdefault(major, []).append({
                "name":              name,
                "purl":              f"pkg:rpm/rocky/{name}?distro=rocky-{major}",
                "affected_state":    "affected",
                "remediation_state": "fixed",
                "status_raw":        "fixed",
                "source":            "rocky",
                "advisory":          adv_id,
                "vendor_data":       {"cpe": f"cpe:2.3:o:rocky:rocky_linux:{major}:*:*:*:*:*:*:*"},
                "severity":          severity,
                "ranges":            [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fix_ver}]}],
            })

        if not pkgs_by_major:
            continue

        adv_obj = {
            "id":        adv_id,
            "synopsis":  adv.get("synopsis", ""),
            "severity":  severity,
            "published": published,
            "updated":   updated,
        }

        for cve_id in cve_ids:
            for major, packages in pkgs_by_major.items():
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
                            by_cve[k]["pkg_map"][p["purl"]] = p
                    if adv_id not in {a["id"] for a in by_cve[k]["advisories"]}:
                        by_cve[k]["advisories"].append(adv_obj)

    for (cve_id, major), info in by_cve.items():
        adv_list = info["advisories"]
        primary  = adv_list[0] if adv_list else {}

        history: list = []
        for a in adv_list:
            if a.get("published"):
                history.append({
                    "date":   a["published"],
                    "event":  "advisory_added",
                    "source": "rocky",
                    "detail": a["id"],
                })
            if a.get("updated") and a.get("updated") != a.get("published"):
                history.append({
                    "date":   a["updated"],
                    "event":  "advisory_updated",
                    "source": "rocky",
                    "detail": a["id"],
                })

        yield {
            "aliases":      [cve_id] + [a["id"] for a in adv_list],
            "cve":          {"cve_id": cve_id},
            "titles":       ([{"value": primary["synopsis"], "source": "rocky", "advisory": primary["id"]}]
                             if primary.get("synopsis") else []),
            "descriptions": [],
            "cvss":         [],
            "cwes":         [],
            "references":   [],
            "advisories":   [
                {
                    "@id":       a["id"],
                    "source":    "rocky",
                    "url":       f"https://errata.rockylinux.org/{a['id']}",
                    "published": a["published"],
                    "updated":   a["updated"],
                }
                for a in adv_list
            ],
            "upstream":     [],
            "packages":     list(info["pkg_map"].values()),
            "exploits":     [],
            "notices":      [],
            "history":      history,
        }
