# Rocky Linux

Rocky Linux advisories (RLSA) are ingested from the **RESF Apollo API**, the official
Rocky Linux errata service.

## Apollo API
- **URL:** `https://apollo.build.resf.org/api/v3/advisories`
- **Official:** Yes — Rocky Enterprise Software Foundation (RESF)
- **Format:** JSON (paginated, 100 advisories per page)
- **Local path:** `advisories.json` (all pages concatenated into a single array)
- **Sync:** full paginated fetch on every sync run
- **Content:** RLSA-\* (Rocky Linux Security Advisories) with their CVE list, per-CVE
  CVSS3 vectors and base scores, CWE ids, advisory severity, synopsis, published/updated
  timestamps. Only `kind = "Security"` advisories carry CVEs and are relevant here.
  Per-package fix data is a later phase.

```
advisories[] (one object per RLSA)/
├── name                                ✅ → advisory.advisory_id  (e.g. RLSA-2024:1234)
├── synopsis                            ✅ → advisory.title
├── severity                            ✅ → advisory.severity
├── published_at                        ✅ → advisory.published
├── updated_at                          ✅ → advisory.modified
└── cves[]/
    ├── cve                             ✅ → advisory_cve.cve_id + cve spine
    ├── cvss3_scoring_vector            ✅ → cve_cvss.vector
    ├── cvss3_base_score                ✅ → cve_cvss.base_score  (computed from vector when absent)
    └── cwe                             ✅ → cve_cwe.cwe_id  (first token, e.g. CWE-79)

(other fields)                          ✗  not imported

Legend: ✅ imported  ✗ not imported (yet)
```

## Notes

- Rocky Linux is not a CNA. `cve_cvss` and `cve_cwe` rows are written with
  `origin='rocky'` and `source=NULL` (no CNA orgId). Duplicate `(cve_id, vector)` pairs
  across advisories are de-duplicated in code (since `source=NULL` defeats the
  `ON CONFLICT` unique index).
- `cve_vendor.data.severity` is set to the highest RLSA severity seen for each CVE across
  all advisories (Critical > Important > Moderate > Low). This feeds the
  [downstream tier](../advisory-tiers.md) `cve_levels()` assessment.
- Rocky Linux rebuilds Red Hat errata; each RLSA typically corresponds to a RHSA, but the
  RHSA cross-reference is not extracted into a structured field.
- Advisory URLs are constructed at import time: `https://errata.rockylinux.org/<RLSA-name>`.
  The `source_urls.json` entry (`cve_url = https://errata.rockylinux.org/cve/{cve}`) drives
  the per-CVE tracking link in `cve_levels()`.
- Affected/fixed package status (purls, version ranges) is a later phase and not
  written yet.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ❌
cve_cvss           ✅  cves[].cvss3_scoring_vector / cvss3_base_score
cve_cwe            ✅  cves[].cwe
cve_ref            ❌
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ✅  RLSA — id / title / severity / published / modified / url
advisory_cve       ✅  RLSA ↔ CVE
cve_vendor         ✅  {"severity": "<highest RLSA severity for this CVE>"}
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
