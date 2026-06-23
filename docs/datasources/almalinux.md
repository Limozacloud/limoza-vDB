# AlmaLinux

AlmaLinux publishes its security advisories (ALSA) as a JSON errata feed, one file
per major release.

## Errata JSON
- **URL:** `https://errata.almalinux.org/<major>/errata.full.json`
- **Official:** Yes — AlmaLinux OS Foundation-maintained
- **Format:** JSON array of errata objects per major release
- **Local path:** `<major>.json` (e.g. `8.json`, `9.json`, `10.json`)
- **Sync:** full re-download of each major's file on every sync run. Major releases synced: 8, 9, 10.
- **Content:** ALSA-\* (AlmaLinux Security Advisories) with their CVE references, advisory
  severity, title, issued/updated dates. Only errata with CVE references are imported.
  Per-package fix data is a later phase.

```
errata[] (one object per ALSA)/
├── id                                  ✅ → advisory.advisory_id  (e.g. ALSA-2024:1234)
├── severity                            ✅ → advisory.severity
├── title                               ✅ → advisory.title
├── issued_date                         ✅ → advisory.published
├── updated_date                        ✅ → advisory.modified
└── references[]/
    └── [type=cve].id                   ✅ → advisory_cve.cve_id + cve spine

(other fields)                          ✗  not imported

Legend: ✅ imported  ✗ not imported (yet)
```

## Notes

- AlmaLinux is not a CNA and its errata feed carries no structured CVSS or CWE data.
  Those fields must come from other sources (e.g. the CVE List).
- AlmaLinux rebuilds Red Hat errata; each ALSA typically corresponds to a RHSA, but the
  RHSA cross-reference is not extracted into a structured field.
- Advisory URLs are constructed at import time:
  `https://errata.almalinux.org/<major>/<ALSA-with-colon-as-dash>.html`.
- `cve_vendor.data.severity` is set to the highest ALSA severity seen for each CVE
  across all advisories (Critical > Important > Moderate > Low). This feeds the
  [downstream tier](../advisory-tiers.md) `cve_levels()` assessment.
- Affected/fixed package status (purls, version ranges) is a later phase and not
  written yet.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ❌
cve_cvss           ❌
cve_cwe            ❌
cve_ref            ❌
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ✅  ALSA — id / title / severity / published / modified / url
advisory_cve       ✅  ALSA ↔ CVE
cve_vendor         ✅  {"severity": "<highest ALSA severity for this CVE>"}
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
