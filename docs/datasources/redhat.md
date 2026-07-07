# Red Hat

Red Hat publishes its security data as CSAF 2.0. Two feeds are consumed: the **VEX**
feed (one file per CVE) carries the per-CVE enrichment and the advisory links; the
**advisories** feed (one file per RHSA) fills in each bulletin's title, severity, and
dates.

## CSAF-VEX
- **URL:** `https://security.access.redhat.com/data/csaf/v2/vex`
- **Official:** Yes — Red Hat-maintained
- **Format:** CSAF 2.0 JSON (VEX profile), one file per CVE
- **Local path:** `vex/<year>/cve-<year>-<id>.json`
- **Sync:** full archive (`csaf_vex_YYYY-MM-DD.tar.zst`) on first run, incremental via `changes.csv` afterwards
- **Content:** severity, CVSS, CWE, references, mitigations, and the RHSA links per CVE

```
vulnerabilities[]/
├── cve                                 ✅ → advisory_cve.cve_id + cve spine
├── cwe.id                              ✅ → cve_cwe.cwe_id
├── notes[description|general].text     ✅ → cve_desc.value
├── notes[other].text (statement)       ✅ → cve_impact.description
├── scores[].cvss_v3 {baseScore,
│     vectorString, version, baseSeverity}  ✅ → cve_cvss.{base_score,vector,version,severity}
├── references[].{url, category}        ✅ → cve_ref.{url, type}
├── remediations[vendor_fix].url        ✅ → advisory.advisory_id + advisory.url (RHSA)
├── remediations[workaround].details    ✅ → cve_workaround.value
├── remediations[mitigation].details    ✅ → cve_solution.value
├── threats[impact].details             ✅ → cve_impact.description (fallback)
├── product_status / product_tree       ✅ → affected (coord=purl) — full VEX status + fix versions
└── document.aggregate_severity.text    ✅ → cve_vendor.data.severity

Legend: ✅ imported  ✗ not imported
```

## CSAF-Advisories
- **URL:** `https://security.access.redhat.com/data/csaf/v2/advisories`
- **Official:** Yes — Red Hat-maintained
- **Format:** CSAF 2.0 JSON (CSAF profile), one file per RHSA/RHBA/RHEA
- **Local path:** `advisories/<year>/rhsa-<year>_<id>.json`
- **Sync:** full archive on first run, incremental via `changes.csv` afterwards
- **Content:** per-advisory title, severity, and dates — backfilled onto the `advisory`
  rows the VEX feed created (no new rows)

```
document/
├── tracking.id                         ✅ → advisory.advisory_id (match)
├── title                               ✅ → advisory.title
├── aggregate_severity.text             ✅ → advisory.severity
├── tracking.initial_release_date       ✅ → advisory.published
└── tracking.current_release_date       ✅ → advisory.modified
```

## Notes

- The VEX feed seeds the `advisory` rows (via `remediations[vendor_fix].url`); the
  advisories feed then fills their title/severity/dates.
- Advisory types: RHSA = security, RHBA = bugfix, RHEA = enhancement — only RHSA
  carries CVEs and is relevant here.
- Red Hat's per-CVE `aggregate_severity` becomes the `cve_vendor` assessment, which
  feeds the [downstream tier](../advisory-tiers.md) (`source_urls.json` maps
  `redhat` → `access.redhat.com/security/cve/{cve}`).
- RHSA advisories are the upstream reference for [AlmaLinux](almalinux.md) and
  [Rocky Linux](rocky.md), whose errata rebuild Red Hat's fixes.
- Red Hat's CSAF VEX is the reference for the [affected layer](../affected-versions.md):
  `product_status` (known_affected / known_not_affected / fixed) + `product_tree` →
  `affected` rows (`coord=purl`), with `no_fix_planned` remediations mapped to `wont_fix`.
  AlmaLinux, Rocky and Oracle Linux inherit these ranges.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ✅  vulnerabilities[].notes[description|general]
cve_cvss           ✅  vulnerabilities[].scores[].cvss_v3
cve_cwe            ✅  vulnerabilities[].cwe.id
cve_ref            ✅  vulnerabilities[].references[]
cve_solution       ✅  remediations[mitigation].details
cve_workaround     ✅  remediations[workaround].details
cve_impact         ✅  notes[other] statement / threats[impact].details
cve_alias          ❌
advisory           ✅  RHSA — id/url (VEX) + title/severity/dates (advisories feed)
advisory_cve       ✅  RHSA ↔ CVE
cve_vendor         ✅  {"severity": aggregate_severity}
affected           ✅  product_status + product_tree → coord=purl (status incl. wont_fix; reference impl.)
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
