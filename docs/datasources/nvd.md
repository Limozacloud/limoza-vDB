# NVD

The National Vulnerability Database (NVD) enriches each CVE with its own descriptions,
CVSS scores, CWE weaknesses, and references — and, crucially, with **CPE applicability**
(`configurations[].nodes[].cpeMatch[]`), the version ranges that CNA records usually lack.
NVD is therefore the **authoritative CPE source** for the [affected-version layer](../affected-versions.md):
it drives the `cpe` lane for unmanaged/binary software (openssl, curl, zlib, vendor
binaries, …) that no package manager or distro advisory covers.

NVD does **not** own the `cve` spine — the record (assigner/title/dates) stays with the
[CVE List](cvelistv5.md). NVD writes alongside it as a multi-source enricher.

## NVD CVE 2.0 (per-CVE JSON)

- **URL:** `https://github.com/Limozacloud/nvd-mirror` (shallow git clone; mirrors the NVD
  CVE 2.0 feeds to per-CVE JSON)
- **Official:** mirror of NVD (NIST) data
- **Format:** NVD CVE 2.0 JSON, one file per CVE
- **Local path:** `repo/data/CVE-<year>/…/CVE-<year>-<id>.json`
- **Sync:** `git clone --depth=1` / `git pull`; incremental ingest reparses only the
  changed CVEs (git head diff)
- **Content:** descriptions, CVSS (v3.1/v3.0/v2/v4.0), CWE, references, and the CPE
  applicability statements that become the `affected` cpe lane

```
cve/
├── id                                ✅ → cve spine (cve.cve_id) — spine only, NOT cve_record
├── descriptions[]                    ✅ → cve_desc.value  (per lang; origin=source=nvd)
├── metrics.cvssMetricV31/30/2/40[]   ✅ → cve_cvss.{version, base_score, severity, vector}
├── weaknesses[].description[]        ✅ → cve_cwe.cwe_id  (CWE-* only)
├── references[]                      ✅ → cve_ref.{url, type}
└── configurations[].nodes[].cpeMatch[]   ✅ → affected (coord=cpe) — the CPE lane
    ├── criteria (cpe:2.3:…)              → affected.cpe23 (NVD-validated via cpe_norm)
    ├── versionStartIncluding/Excluding   → introduced
    ├── versionEndExcluding                → fixed         (exclusive upper)
    ├── versionEndIncluding                → last_affected (inclusive upper)
    └── bare version in criteria           → exact (last_affected = that version)

Legend: ✅ imported  ✗ not imported
```

## Affected versions (L4) — the CPE lane

The `nvd` extractor (`ingest/affected/sources/nvd.py`) turns every **vulnerable**
`cpeMatch` into an `affected` row (`coord=cpe`, `version_scheme=generic`):

- **CPE → canonical.** Each `criteria` CPE is resolved + **validated against the NVD
  catalogue** by [`cpe_norm`](../affected-versions.md#cpe-validation), so a stored row and
  a scanned component land on the same key.
- **Ranges.** `versionStartIncluding`/`Excluding` → `introduced`;
  `versionEndExcluding` → `fixed`; `versionEndIncluding` → `last_affected`; a bare version
  in the criteria → an exact match. A CPE with no version information is too broad and is
  skipped.
- **Microsoft excluded.** CPEs with vendor `microsoft` are dropped — [MSRC](microsoft.md)
  is the authoritative source for those build numbers.

This is the primary CPE source; the [CVE List](cvelistv5.md) CPE synthesis only fills
CVEs that NVD has no configuration for.

## Notes

- **`origin` and `source` are both `nvd`** across the enrichment rows and the affected
  cpe lane (the delete-scope key).
- NVD does **not** write `cve_record` — the spine record is the CVE List's. NVD only
  registers the `cve_id` in the spine and attaches its enrichment.
- The metadata ingest is parallelised (one DB connection per worker) and incremental: on
  a repeat run only the CVEs whose files changed since the last git head are reparsed.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ✅  descriptions[] (per lang)
cve_cvss           ✅  metrics.cvssMetricV31/30/2/40
cve_cwe            ✅  weaknesses[].description (CWE-*)
cve_ref            ✅  references[]
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ❌
advisory_cve       ❌
cve_vendor         ❌
affected           ✅  configurations[].cpeMatch → coord=cpe (authoritative CPE lane; Microsoft excluded)
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
