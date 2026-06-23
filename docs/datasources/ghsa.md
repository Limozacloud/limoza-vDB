# GitHub Security Advisories (GHSA)

GHSA is the **L2 ecosystem upstream advisory** source. It is the GitHub Security
Advisory Database, distributed in OSV format. For any CVE that affects a language
ecosystem package (npm, PyPI, Go, Maven, crates.io, NuGet, RubyGems, …), the GHSA
record is the upstream advisory issued by the ecosystem maintainer — the same role
that an RHSA plays for Red Hat packages. Advisories without a CVE alias are skipped;
the database is CVE-centric.

GHSA contributes the richest ecosystem-level enrichment: CVSS, CWE, a full
description, and the set of affected package PURLs with version ranges. The PURLs are
written to `cve_vendor.data` as a phase-2 staging area pending the phase-3 affected
table.

## github/advisory-database

- **URL:** `https://github.com/github/advisory-database`
- **Official:** Yes — GitHub-maintained
- **Format:** OSV (JSON), one advisory per file
- **Local path:** `{ghsa}/advisories/github-reviewed/<year>/<id>/GHSA-*.json`
- **License:** CC BY 4.0
- **Sync:** sparse `git clone --depth=1 --filter=blob:none` on first run; `git pull --ff-only` afterwards. Only the `advisories/github-reviewed` subtree is checked out and ingested.
- **Content:** human-reviewed advisories for ecosystem packages with CVSS scores, CWE ids, a full markdown description, and affected package PURLs with version ranges.

```
osv/
├── id                                  ✅ → advisory.advisory_id (GHSA-ID)
│                                           + advisory.url  (https://github.com/advisories/{id})
├── withdrawn                           ✅ → record skipped entirely if present
├── aliases[]/
│   └── [CVE-*]                         ✅ → cve spine (cve.cve_id) + advisory_cve.cve_id
│                                           (no CVE alias → record skipped)
├── summary                             ✅ → advisory.title
├── details                             ✅ → cve_desc.value  (preferred; falls back to summary if blank)
├── database_specific/
│   └── severity                        ✅ → advisory.severity  (CRITICAL/HIGH/MODERATE/LOW/null)
├── published                           ✅ → advisory.published
├── modified                            ✅ → advisory.modified
├── severity[]/
│   ├── type (CVSS_V4/V3/V2)            ✅ → cve_cvss.version (4.0 / 3.1 / 2.0)
│   └── score (vector string)           ✅ → cve_cvss.vector + cve_cvss.{base_score, severity}
│                                           (v2 and v4 vectors: score_from_vector returns None → skipped)
├── database_specific/
│   └── cwe_ids[]                       ✅ → cve_cwe.cwe_id  (CWE-* only)
└── affected[]/
    ├── package/
    │   ├── purl                        ✅ → cve_vendor.data.packages[].purl  (used verbatim if present)
    │   ├── ecosystem                   ✅ → cve_vendor.data.packages[].purl  (mapped when no purl field)
    │   └── name                        ✅ → cve_vendor.data.packages[].purl
    └── ranges[]/
        └── events[introduced|fixed|last_affected]  ✅ → cve_vendor.data.packages[].ranges (compact string)

Legend: ✅ imported  ✗ not imported
```

## PURL

GHSA emits **ecosystem PURLs** derived from `affected[].package.ecosystem` + `name`.
If the source record already supplies a `package.purl` field it is used verbatim.
An unmapped ecosystem with no purl hint yields no PURL and that affected entry is
dropped from the package list.

| GHSA ecosystem | PURL type |
|---|---|
| `PyPI` | `pkg:pypi/<name>` (lowercased) |
| `npm` | `pkg:npm/<name>` |
| `Go` | `pkg:golang/<name>` |
| `Maven` | `pkg:maven/<name>` |
| `RubyGems` | `pkg:gem/<name>` |
| `crates.io` | `pkg:cargo/<name>` |
| `NuGet` | `pkg:nuget/<name>` |
| `Packagist` | `pkg:composer/<name>` |
| `Pub` | `pkg:pub/<name>` |
| `Hex` | `pkg:hex/<name>` |
| `Hackage` | `pkg:hackage/<name>` |
| `SwiftURL` | `pkg:swift/<name>` |
| `Bitnami` | `pkg:bitnami/<name>` |
| `GitHub Actions` | `pkg:github/<name>` |
| (any other) | none — entry skipped |

These PURLs are package identities (no version). Version ranges from `affected[].ranges[]`
are compacted into a human-readable string (`>=introduced <fixed` / `<=last_affected`)
and stored alongside the purl in `cve_vendor.data.packages[].ranges`. Full version
range semantics belong to the phase-3 affected table.

## cve_vendor layout

Each CVE that appears in at least one GHSA record gets one `cve_vendor` row with
`source = 'ghsa'`:

```json
{
  "packages": [
    { "purl": "pkg:pypi/pillow", "ranges": ">=9.0.0 <9.0.1" },
    { "purl": "pkg:pypi/pillow", "ranges": ">=8.0.0 <8.3.2" }
  ],
  "ghsa": ["GHSA-xxxx-yyyy-zzzz"]
}
```

`packages` is deduplicated by `(purl, ranges)` across all GHSA advisories that
reference the same CVE. `ghsa` is the list of GHSA ids that contributed to this CVE.

The `cve_levels()` function uses the first purl in `cve_vendor.data.packages` to label
the L2 upstream advisory with the ecosystem package name.

## Notes

- **`origin` and `source` are both `"ghsa"`.** The `source` column in `cve_cvss` /
  `cve_cwe` / `cve_desc` enrichment rows is set to GitHub's CNA UUID (looked up via
  `cna.short_name = 'github_m'`); `origin` is the literal string `"ghsa"`.
- **One `cve_desc` row per CVE**, written from `details` (markdown). When multiple
  GHSA advisories cover the same CVE, only the first encountered is written
  (`seen_desc` deduplication by `cve_id`).
- **CVSS** is written only when `score_from_vector` can parse a numeric score from
  the vector string. v2 and v4 vectors return `(None, None)` and are skipped.
  Duplicate `(cve_id, vector)` pairs across advisories are dropped.
- **Unreviewed advisories** (`advisories/unreviewed/`) are **not** ingested — only
  `github-reviewed` is in the sparse checkout.
- **GHSA-only advisories** (no `CVE-*` alias) are skipped. The database is CVE-centric.
- GHSA is the **L2 upstream advisory** in the [advisory tier](../advisory-tiers.md)
  model. OSV native ecosystem DBs (PYSEC, GO, RUSTSEC, EEF, DRUPAL) are L3 downstream
  and handled by the [OSV importer](osv.md).

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ✅  details (or summary fallback; en; one row per CVE)
cve_cvss           ✅  severity[].{type, score}  (parsed vector + derived score)
cve_cwe            ✅  database_specific.cwe_ids[]
cve_ref            ❌  not written
cve_solution       ❌  not written
cve_workaround     ❌  not written
cve_impact         ❌  not written
cve_alias          ❌  not written
advisory           ✅  GHSA-ID / url / title / severity / published / modified
advisory_cve       ✅  GHSA-ID ↔ CVE links (one row per CVE per advisory)
cve_vendor         ✅  {"packages": [{purl, ranges}], "ghsa": [GHSA-IDs]}
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
