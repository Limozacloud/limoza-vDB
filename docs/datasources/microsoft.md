# Microsoft

## MSRC CVRF API v3.0 (the only ingested feed)
- **URL (sync):** `https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{release}` (e.g. `2025-Jun`)
- **Updates index:** `https://api.msrc.microsoft.com/cvrf/v2.0/updates`
- **Advisory URL (stored):** `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{advisory_id}`
- **Official:** Yes — Microsoft-maintained
- **Format:** CVRF JSON (requested with `Accept: application/json`)
- **Local path:** `{msrc}/cvrf/{release}.json`
- **Sync:** fetch the updates index, then download each monthly bulletin not already on disk (optional `since` year filter). One document per month (Patch Tuesday) containing every advisory for that month.
- **Content:** per-CVE affected product IDs, CVSS score sets, CWE, severity (Critical/Important/Moderate/Low via Threats type 3), and `VendorFix` remediations (type 2) carrying KB numbers / fixed builds. Product IDs are resolved to product names via the document's `ProductTree.FullProductName`, then mapped to PURL/CPE by `purl.py`.

> **Note on the other Microsoft feeds.** The MSRC CSAF feed and the standalone Azure Linux / CBL-Mariner OVAL repository are *not* ingested by this module — there is no CSAF or OVAL transform. Azure Linux / CBL-Mariner PURLs are only ever produced when such a product name happens to appear inside a CVRF document (rare), via the RPM branches of `purl.py`.

```
DocumentTracking/
├── Identification.ID.Value           ✅ → advisories[].@id + per-record advisory tag
├── InitialReleaseDate                ✅ → advisories[].published + history[].date
└── CurrentReleaseDate                ✅ → advisories[].updated

ProductTree/
└── FullProductName[]
    ├── ProductID                     ✅ → {ProductID: Value} lookup (resolves Remediations[].ProductID)
    └── Value (product name)          ✅ → purl.py derive_identifiers() → packages[].purl + vendor_data.cpe/product_name

Vulnerability[]/                      (one or more LVE records produced per vulnerability)
├── CVE                               ✅ → aliases[]
│   ├── "CVE-..."                       → alias = the CVE itself
│   └── "ADV..."                        → alias = each CVE found in the type-2 note text (fans out to one record per CVE);
│                                          falls back to the ADV id if the note lists none. ADV id added as a second alias.
├── Title.Value                       ✅ → titles[].value  (advisory_ref = advisory id)
├── Notes[?Type==2].Value | [0]
│   ├── (HTML-stripped)               ✅ → descriptions[].value
│   └── (CVE-regex scan, ADV only)    ✅ → aliases[] expansion (see CVE above)
├── CWE.ID                            ✅ → cwes[].id  (advisory = advisory id)
├── CVSSScoreSets[]/
│   ├── BaseScore                     ✅ → cvss[].score
│   ├── Vector                        ✅ → cvss[].vector + cvss[].version (parsed from "CVSS:x.y/..." prefix, default 3.1)
│   └── ProductID | [0]               ✅ → cvss[].product_id  (advisory = advisory id)
├── Threats[?Type==3].Description.Value  ✅ → severity (Critical/Important/Moderate/Low → critical/high/medium/low, max wins)
│                                          → packages[].severity + advisories[].vendor_data.severity
├── Remediations[?Type==2]/           (VendorFix → the only package source)
│   ├── ProductID[]                   ✅ → packages[] (one per resolvable product; deduped by (purl, Description))
│   ├── Description.Value             ✅ → KB number when all-digits → packages[].name version "KB<n>" + vendor_data.kb_*
│   ├── FixedBuild                    ✅ → packages[].ranges[].events[].fixed (ignored if it is a URL); vendor_data.fixed_build
│   ├── Supercedence                  ✅ → packages[].vendor_data.supercedence
│   ├── SubType                       ✅ → packages[].vendor_data.sub_type (default "Security Update")
│   └── RestartRequired.Value         ✅ → packages[].vendor_data.restart_required (== "Yes")
├── Remediations[?Type==3].URL        ✅ → references[].url  (type always "advisory")
├── Remediations[?Type!=2,3]          ✗  (Workaround / Mitigation / WillNotFix types not consumed)
├── Notes[?Type!=2]                   ✗
├── Acknowledgments / Revisions / ...  ✗
└── (product_status equivalent)       ✗  (CVRF has no not_affected channel here — only VendorFix packages emitted)

Legend: ✅ imported  ✗ not imported
```

## PURL
PURLs are derived from the resolved product name by `purl.py:derive_identifiers()`, which also
returns a best-effort CPE. The CPE is validated against the NVD dictionary (`ingest.cpe.validate`);
if it is not found it is dropped and a `cpe_not_found` notice is emitted.

- **Windows OS / applications:** `pkg:generic/microsoft/<slug>[@<version>][?arch=...&variant=...]`
  - e.g. `pkg:generic/microsoft/windows-11@24h2?arch=x64`, `pkg:generic/microsoft/windows-server-2022?variant=server-core`,
    `pkg:generic/microsoft/exchange-server@2019`, `pkg:generic/microsoft/sql-server@2022`,
    `pkg:generic/microsoft/dotnet-framework@4.8`.
- **Azure Linux / CBL-Mariner RPMs** (only when present in a CVRF doc):
  `pkg:rpm/azurelinux/<pkg>@<version>` or `pkg:rpm/cbl-mariner/<pkg>@<version>`.
- **Azure Linux / CBL-Mariner platform nodes** (e.g. "Azure Linux 3.0") are skipped — they
  resolve to `(None, None)` and produce a `missing_purl` notice.

The package PURL carries no version for Windows products (it is a product identity); the KB
number (`KB<n>`) or fixed build is recorded in `packages[].ranges[].events[].fixed`. RPM PURLs
do carry a version in the `@` segment.

## State mapping

CVRF (as ingested) emits packages from a single channel — `Remediations` of type 2 (VendorFix).
There is no not-affected / will-not-fix channel consumed, so every emitted package is fixed.

| CVRF source | `affected_state` | `remediation_state` | `status_raw` |
|---|---|---|---|
| `Remediations[Type==2]` (VendorFix) | `affected` | `fixed` | `fixed` |

## Notes
- **`cve` is deliberately set to `None`.** Microsoft is not authoritative for CVE metadata; the CVE id is carried only in `aliases[]`, and the CVE record itself is seeded by other sources (NVD).
- **`ADV` advisories fan out.** When `Vulnerability.CVE` is an `ADV...` id, the type-2 note text is scanned for `CVE-YYYY-NNNN` patterns and **one LVE record is produced per discovered CVE**; the `ADV` id is added as a secondary alias. If no CVE is found in the note, a single record keyed by the `ADV` id is produced.
- **Missing PURLs are surfaced as notices.** When a product name cannot be mapped to a PURL, a `missing_purl` notice is appended (`{type, source, message, metadata:{product_id, product_name, advisory_id}}`); when a derived CPE is not in the NVD dictionary, a `cpe_not_found` notice is appended and the CPE is dropped. These flow through to `notices[]` on the record.
- **Severity** is taken from `Threats` type 3 (the textual severity), not from CVSS; when several are present the highest wins.
- **No package granularity below the product.** Windows products are the unit; the "fix version" is the KB article (`KB<n>`) or the `FixedBuild` string.
- `mitigations`, `impacts`, and `upstream` are always emitted empty for this source. `exploits` is empty (the `exploitabilityIndex` / `knownExploited` enrichment described historically is not consumed by this transform).
- Packages are deduplicated by `(purl, Description.Value)` within a vulnerability.

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  (CVRF) [<CVE id>] or expanded CVEs from ADV note text (+ ADV id)
├── has_exploit                  ❌  not written — no exploit data consumed
│
├── cve{}                        ❌  set to None (Microsoft is not authoritative for CVE metadata)
│   ├── cve_id                   ❌
│   ├── status                   ❌
│   ├── published                ❌
│   ├── updated                  ❌
│   ├── epss{}                   ❌  FIRST EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ✅  (CVRF) Vulnerability.Title.Value  (advisory = advisory id)
├── descriptions[]              ✅  (CVRF) Notes[Type==2].Value (HTML-stripped)  (advisory = advisory id)
├── cvss[]                       ✅  (CVRF) CVSSScoreSets[].{BaseScore,Vector,version,product_id}  (advisory = advisory id)
├── cwes[]                       ✅  (CVRF) CWE.{ID,Value}  (advisory = advisory id)
├── references[]                 ✅  (CVRF) Remediations[Type==3].URL  (type "advisory")
│
├── advisories[]
│   ├── @id                      ✅  (CVRF) DocumentTracking.Identification.ID.Value (e.g. 2025-Jun)
│   ├── source                   ✅  "microsoft"
│   ├── url                      ✅  https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<id>
│   ├── published                ✅  DocumentTracking.InitialReleaseDate
│   ├── updated                  ✅  DocumentTracking.CurrentReleaseDate
│   ├── packages                 ✅  list of distinct package PURLs in the record
│   └── vendor_data              ✅  {"severity": "<mapped>"}
│
├── upstream[]                   ❌  not written (emitted empty)
│
├── packages[]
│   ├── name                     ✅  package/product slug parsed from the PURL
│   ├── purl                     ✅  purl.py derive_identifiers() (no version for Windows; @version for RPMs)
│   ├── affected_state           ✅  always "affected" (VendorFix channel only)
│   ├── remediation_state        ✅  always "fixed"
│   ├── status_raw               ✅  "fixed"
│   ├── vex_justification        ❌  not written (CVRF VendorFix has no justification)
│   ├── ranges                   ✅  [{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"KB<n>" | <FixedBuild>}]}]; null if neither
│   ├── severity                 ✅  Threats[Type==3] mapped severity
│   ├── source                   ✅  "microsoft"
│   ├── advisory                 ✅  advisory id (e.g. 2025-Jun)
│   ├── upstream                 ❌
│   └── vendor_data              ✅  {cpe, product_id, product_name, kb_number, kb_url, supercedence, fixed_build, sub_type, restart_required}
│
├── mitigations[]                ❌  not written (emitted empty) — Mitigation/Workaround remediation types not consumed
├── impacts[]                    ❌  not written (emitted empty)
├── exploits[]                   ❌  not written (emitted empty)
│
├── notices[]                    ✅  missing_purl + cpe_not_found  {type, source, message, metadata{}}
│
└── history[]
    ├── date                     ✅  DocumentTracking.InitialReleaseDate (both events)
    ├── event                    ✅  created + advisory_added
    ├── source                   ✅  "microsoft"
    └── detail                   ✅  "LVE created from MSRC <id>" / "MSRC <id> ingested"
```
