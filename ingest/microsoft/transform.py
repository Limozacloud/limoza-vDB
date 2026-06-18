import re
import json
import jmespath
from ingest.mapping import apply_mapping, strip_html, map_severity
from ingest.cpe import validate as _cpe_validate
from .purl import derive_identifiers

_CVE_RE = re.compile(r'CVE-\d{4}-\d+')


def _cvss_version(item):
    v = item.get("Vector", "")
    return v.split("/")[0].split(":")[1] if v.startswith("CVSS:") else "3.1"


def _extract_packages(remediations, ctx):
    product_tree = ctx["product_tree"]
    advisory_id  = ctx["advisory_id"]
    packages, seen = [], set()

    for rem in (remediations or []):
        if rem.get("Type") != 2:
            continue
        desc_value  = rem.get("Description", {}).get("Value", "")
        fixed_build = rem.get("FixedBuild")
        is_kb       = desc_value.isdigit()
        if fixed_build and fixed_build.startswith("http"):
            fixed_build = None

        for product_id in rem.get("ProductID", []):
            product_name = product_tree.get(product_id, "")
            purl, cpe = derive_identifiers(product_name)
            if not purl:
                ctx.setdefault("notices", []).append({
                    "type":    "missing_purl",
                    "source":  "microsoft",
                    "message": f"No PURL for product: {product_name}",
                    "metadata": {"product_id": product_id, "product_name": product_name, "advisory_id": advisory_id},
                })
                continue
            if cpe and not _cpe_validate.is_valid(cpe):
                ctx.setdefault("notices", []).append({
                    "type":    "cpe_not_found",
                    "source":  "microsoft",
                    "message": f"CPE not in NVD dictionary: {cpe}",
                    "metadata": {"cpe": cpe, "product_name": product_name, "advisory_id": advisory_id},
                })
                cpe = None
            key = (purl, desc_value)
            if key in seen:
                continue
            seen.add(key)
            pkg_name = purl.split("/")[-1].split("@")[0]
            fix_ver = f"KB{desc_value}" if is_kb else fixed_build
            packages.append({
                "name":        pkg_name,
                "purl":              purl,
                "affected_state":    "affected",
                "remediation_state": "fixed",
                "status_raw":        "fixed",
                "source":            "microsoft",
                "severity":    None,
                "vendor_data": {
                    "cpe":              cpe,
                    "product_id":       product_id,
                    "product_name":     product_name,
                    "kb_number":        desc_value if is_kb else None,
                    "kb_url":           f"https://support.microsoft.com/help/{desc_value}" if is_kb else None,
                    "supercedence":     rem.get("Supercedence"),
                    "fixed_build":      fixed_build,
                    "sub_type":         rem.get("SubType", "Security Update"),
                    "restart_required": rem.get("RestartRequired", {}).get("Value") == "Yes",
                },
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fix_ver}]}]
                          if fix_ver else None,
            })
    return packages


def _cvss_product_id(item):
    ids = item.get("ProductID") or []
    return ids[0] if ids else None


_MAPPING = [
    ("CWE",           "cwes",     {"id": "ID", "name": "Value"},                                                                       {"source": "microsoft"}),
    ("CVSSScoreSets", "cvss",     {"score": "BaseScore", "vector": "Vector", "version": _cvss_version, "product_id": _cvss_product_id}, {"source": "microsoft"}),
    ("Remediations",  "packages", _extract_packages),
]


def parse(raw: bytes) -> dict:
    return json.loads(raw)


def transform(doc: dict) -> list[dict]:
    advisory_id  = jmespath.search("DocumentTracking.Identification.ID.Value", doc)
    published    = jmespath.search("DocumentTracking.InitialReleaseDate", doc)
    updated      = jmespath.search("DocumentTracking.CurrentReleaseDate", doc)
    product_tree = {
        p["ProductID"]: p["Value"]
        for p in jmespath.search("ProductTree.FullProductName", doc) or []
    }
    ctx          = {"advisory_id": advisory_id, "published": published, "product_tree": product_tree}
    advisory_ref = {"@id": advisory_id}

    records = []
    for vuln in doc.get("Vulnerability", []):
        cve_field = vuln.get("CVE") or ""
        if not cve_field:
            continue

        if cve_field.startswith("CVE-"):
            cve_aliases = [cve_field.upper()]
        elif cve_field.startswith("ADV"):
            notes_text  = jmespath.search("Notes[?Type==`2`].Value | [0]", vuln) or ""
            cve_aliases = [c.upper() for c in sorted(set(_CVE_RE.findall(notes_text)))]
            if not cve_aliases:
                cve_aliases = [cve_field.upper()]
        else:
            continue

        ctx["notices"] = []
        record = apply_mapping(vuln, _MAPPING, ctx)

        title       = jmespath.search("Title.Value", vuln)
        description = strip_html(jmespath.search("Notes[?Type==`2`].Value | [0]", vuln), ctx)
        severity    = map_severity(jmespath.search("Threats[?Type==`3`].Description.Value", vuln), ctx)
        references  = [
            {"url": u, "type": "advisory", "source": "microsoft", "advisory": advisory_ref}
            for u in jmespath.search("Remediations[?Type==`3`].URL", vuln) or []
            if u
        ]

        for item in record.get("cvss", []):
            item["advisory"] = advisory_id
        for item in record.get("cwes", []):
            item["advisory"] = advisory_id
        for item in record.get("packages", []):
            item["advisory"]  = advisory_id
            item["severity"]  = severity

        advisory_entry = {
            "@id":       advisory_id,
            "source":    "microsoft",
            "url":       f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{advisory_id}",
            "published": published,
            "updated":   updated,
            "packages":  list({p["purl"] for p in record.get("packages", [])}),
            "vendor_data": {"severity": severity},
        }

        for cve_alias in cve_aliases:
            adv_alias = cve_field.upper() if cve_field.startswith("ADV") else None
            aliases   = [cve_alias] + ([adv_alias] if adv_alias else [])
            rec = dict(record)
            rec.update({
                "aliases":      aliases,
                "cve":          None,
                "titles":       [{"value": title, "source": "microsoft", "advisory": advisory_id}] if title else [],
                "descriptions": [{"value": description, "source": "microsoft", "advisory": advisory_id}] if description else [],
                "references":   references,
                "advisories":   [advisory_entry],
                "upstream":     [],
                "exploits":     [],
                "notices":      ctx.get("notices", []),
                "history": [
                    {"date": published, "event": "created", "source": "microsoft",
                     "detail": f"LVE created from MSRC {advisory_id}"},
                    {"date": published, "event": "advisory_added", "source": "microsoft",
                     "detail": f"MSRC {advisory_id} ingested"},
                ],
            })
            records.append(rec)

    return records
