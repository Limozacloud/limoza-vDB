# Microsoft

Microsoft Security Response Center (MSRC) publishes its monthly security guidance as
CVRF (Common Vulnerability Reporting Framework) JSON. One document per Patch Tuesday
release covers all advisories issued that month. Microsoft is a CNA; its per-CVE
assessments — CVSS, CWE, description, severity, and exploit status — land in the
`cve_*` enrichment tables, while the monthly release itself becomes the `advisory`
row and each referenced CVE becomes an `advisory_cve` link. The per-product **fix
builds** (from the Remediations) drive the [affected-version layer](../affected-versions.md).

## MSRC CVRF v3.0 (monthly releases)

- **URL:** `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{release}` (e.g. `2025-Jun`)
- **Updates index:** `https://api.msrc.microsoft.com/cvrf/v3.0/updates`
- **Official:** Yes — Microsoft-maintained
- **Format:** CVRF JSON (requested with `Accept: application/json`)
- **Local path:** `{microsoft}/{release}.json` (one file per monthly release)
- **Sync:** fetch the updates index; download each monthly release not already on disk. The two most-recent releases are always re-fetched (they are revised after Patch Tuesday). No `since`-year filter.
- **Content:** per-CVE CVSS score sets, CWE list, description (Notes Type 2), severity (Threats Type 3), exploit status (Threats Type 1), impact type (Threats Type 0), and per-product fix builds (Remediations `FixedBuild`) → the [affected-version layer](../affected-versions.md).

```
DocumentTracking/
├── Identification.ID.Value           ✅ → advisory.advisory_id (monthly release id, e.g. "2025-Jun")
│                                         + advisory.url  (https://msrc.microsoft.com/update-guide/releaseNote/{id})
├── DocumentTitle.Value               ✅ → advisory.title
├── InitialReleaseDate                ✅ → advisory.published
└── CurrentReleaseDate                ✅ → advisory.modified

Vulnerability[]/
├── CVE                               ✅ → cve spine (cve.cve_id) + advisory_cve.cve_id
├── CVSSScoreSets[]/
│   ├── Vector                        ✅ → cve_cvss.vector + cve_cvss.version (parsed from "CVSS:x.y/…" prefix)
│   └── BaseScore                     ✅ → cve_cvss.base_score + cve_cvss.severity (derived)
├── CWE[].ID                          ✅ → cve_cwe.cwe_id  (CWE-* only)
├── Notes[Type==2].Value              ✅ → cve_desc.value  (HTML tags stripped; first Type-2 note wins)
├── Threats[Type==3].Description      ✅ → cve_vendor.data.severity  (Critical/Important/Moderate/Low; max across products)
├── Threats[Type==1].Description      ✅ → cve_vendor.data.{exploited, publicly_disclosed, exploitability}
├── Threats[Type==0].Description      ✅ → cve_vendor.data.impact  (STRIDE-like type string; first wins)
├── Remediations[*].FixedBuild        ✅ → affected (coord=cpe) — fix build per product (all SubTypes)
│   ├── ProductID[] → ProductTree CPE ✅ → affected.cpe23 (NVD-validated via cpe_norm)
│   └── Description (Type 2, KB number) ✅ → affected.fix_kb  (e.g. KB5043050)
├── Remediations[Type==3].URL         ✗  not consumed (per-product KB advisory objects)
├── Remediations[*] without FixedBuild ✗ (Workaround / Mitigation / WillNotFix — no version)
└── Notes[Type!=2]                    ✗

Legend: ✅ imported  ✗ not imported
```

## Affected versions (L4)

Microsoft patches by **build number**, not package version. The `microsoft` extractor
(`ingest/affected/sources/microsoft.py`) turns each Remediation that carries a
`FixedBuild` into an `affected` row (`coord=cpe`):

- **Product → CPE.** `ProductTree.FullProductName` maps each `ProductID` to a CPE,
  resolved + **validated against the NVD catalogue** by
  [`cpe_norm`](../affected-versions.md#cpe-validation). MSRC's `windows_server_2012_R2`
  and a scanner's `windows_server_2012` + `update=r2` land on the same key; 2012 and
  2012 R2 stay distinct (builds 6.2.9200 vs 6.3.9600).
- **No-CPE fallback.** Older MSRC products (2019-2021) often carry no CPE; their name is
  resolved via `cpe_norm.from_name()` and validated the same way (covers Windows OS +
  Office 2016+/SQL/Visual Studio).
- **Fix build.** `FixedBuild` → `affected.fixed` (`version_scheme = generic`), so the
  matcher version-compares a host build against it. The KB article shipping that build
  (Remediation Type 2) is captured in `affected.fix_kb` (e.g. `KB5043050`) and surfaced by
  the matcher — a `/match` finding names the exact patch.
- **Rolling products.** Single rolling products with no parallel versions or back-ports
  (Visual Studio Code, Edge) are matched cumulatively — any build below the fix is affected —
  rather than scoped to a `major.minor` line (which suits parallel products like SQL Server,
  Office and Visual Studio).
- **Dropped:** CBL / Azure Linux (Microsoft's own Linux distro — not a CPE product), and
  any product whose CPE can't be validated against NVD.

**Known limit:** apps NVD identifies by year-in-version with no build (Exchange,
SharePoint, Excel, .NET) are matchable only year-coarse via CPE, so they are not emitted.

## Advisory URL

Microsoft's per-CVE tracking page is `https://msrc.microsoft.com/update-guide/vulnerability/{cve}`.
This template is recorded in `source_urls.json` (key `microsoft`, field `cve_url`) so that
`cve_levels()` can surface Microsoft as a downstream vendor even when only a
`cve_vendor` row exists and no formal advisory bulletin was filed for that CVE.

## Notes

- **`origin` and `source` are both `microsoft`.**  The `source` column in `cve_*`
  enrichment rows is set to Microsoft's CNA UUID (looked up via
  `cna.short_name = 'microsoft'`); `origin` is the literal string `"microsoft"` (the
  delete-scope key).
- **Severity** is taken from Threats Type 3 (the textual rating), not derived from
  CVSS. When several threat entries exist the highest rating wins
  (`Critical > Important > Moderate > Low`). It is stored in `cve_vendor.data.severity`.
- **Exploit status** (Threats Type 1) is parsed from a semicolon-separated `Key: Value`
  string. `"Exploited: Yes"` and `"Publicly Disclosed: Yes"` win over any lower value
  across the month's documents. The highest-ranked `"Latest Software Release"` exploitability
  string also survives in `cve_vendor.data.exploitability`.
- **One `advisory` row per monthly release.** All CVEs in that month link to it via
  `advisory_cve`. Product-level KB articles (Remediations Type 2) are phase 3.
- **CVSS deduplication.** Within the full run, duplicate `(cve_id, vector)` pairs are
  dropped; only the first occurrence per vector is written.
- **The MSRC CSAF feed** is not ingested — there is no separate CSAF transform. Only
  the CVRF JSON endpoint is consumed.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ✅  Vulnerability[].Notes[Type==2].Value (HTML-stripped; en)
cve_cvss           ✅  Vulnerability[].CVSSScoreSets[].{Vector, BaseScore}
cve_cwe            ✅  Vulnerability[].CWE[].ID
cve_ref            ❌  not written
cve_solution       ❌  not written
cve_workaround     ❌  not written
cve_impact         ❌  not written
cve_alias          ❌  not written
advisory           ✅  monthly MSRC release (id / url / title / published / modified)
advisory_cve       ✅  release ↔ CVE links
cve_vendor         ✅  {"severity", "impact", "exploited", "publicly_disclosed", "exploitability"}
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
