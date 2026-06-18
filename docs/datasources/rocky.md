# Rocky Linux

Rocky Linux is ingested from **two** feeds that together cover both historical and
recent advisories:

1. **updateinfo.xml** — the repodata `updateinfo` metadata mirrored from the package
   repositories (bulk history).
2. **Apollo API** — the RESF Apollo errata API (recent tail, always current).

Both feeds produce one LVE record per `(CVE, major release)`. Apollo records carry
fewer fields than updateinfo records (see Schema Coverage).

## updateinfo.xml feed
- **URL:** `https://download.rockylinux.org/pub/rocky/<major>/<repo>/x86_64/os/repodata/` — the `updateinfo` file location is discovered from `repomd.xml`.
- **Official:** Yes — Rocky Enterprise Software Foundation repodata
- **Format:** gzipped `updateinfo.xml` (RPM updateinfo metadata)
- **Local path:** `<rocky_errata>/<major>/<repo>.xml` (downloaded as `<repo>.xml.gz`, then decompressed; the `.gz` is removed)
- **Sync:** for each `(major, repo)` the `updateinfo` location is resolved from `repomd.xml`, then a conditional `HEAD` (ETag, falling back to Last-Modified) decides whether to re-download. Majors: 8, 9, 10. Repos: BaseOS, AppStream, NFV. Arch: x86_64.
- **Content:** RLSA-* advisories (`type="security"`) with CVE references, fixed package NVRs, severity, title, description, issued/updated dates, and reference links.

```
<updates>/<update type="security">/
├── id                                ✅ → advisories[].@id + packages[].advisory + history[].detail + aliases[]
├── title                             ✅ → titles[].value
├── description                       ✅ → descriptions[].value
├── severity                          ✅ → packages[].severity (Critical→critical, Important→high, Moderate→medium, Low→low)
├── issued[@date]                     ✅ → advisories[].published + history[].date (event=advisory_added)
├── updated[@date]                    ✅ → advisories[].updated + history[].date (event=advisory_updated, if ≠ published)
├── references/reference[]/
│   ├── [type=cve][@id]               ✅ → cve.cve_id + aliases[]  (must start with "CVE-")
│   ├── [type=bugzilla][@href]        ✅ → references[].url (type=report)
│   ├── [type=self][@href]            ✅ → references[].url (type=advisory)
│   └── (other types)[@href]          ✅ → references[].url (type=web)
└── pkglist/collection/package[]/
    ├── @name                         ✅ → packages[].name + packages[].purl
    ├── @version                      ✅ → packages[].ranges[].events[].fixed (NVR)
    ├── @release                      ✅ → packages[].ranges[].events[].fixed (NVR)
    ├── @epoch                        ✅ → packages[].ranges[].events[].fixed (prefixed "<epoch>:" when ≠ 0)
    └── @arch                         ✗  (arch=src skipped; per-arch dupes collapsed by (name,version,release))

Legend: ✅ imported  ✗ not imported
```

## Apollo API feed
- **URL:** `https://apollo.build.resf.org/api/v3/advisories/?page=<n>&limit=100`
- **Official:** Yes — RESF Apollo errata service
- **Format:** JSON (paginated; `advisories[]`)
- **Local path:** `<rocky_errata>/advisories/<name with ":"→"-">.json` (one file per advisory)
- **Sync:** paged fetch (100/page); incremental via `filters.publishedAfter=<last sync timestamp>` stored in the checkpoint. Only `kind == "Security"` advisories are imported.
- **Content:** RLSA-* advisories with CVE list, per-package NVRAs tagged by product (major release derived from the product name), severity, synopsis, published/updated timestamps.

```
advisories[] (kind="Security")/
├── name                              ✅ → advisories[].@id + packages[].advisory + history[].detail + aliases[]
├── synopsis                          ✅ → titles[].value
├── severity                          ✅ → packages[].severity (mapped)
├── published_at                      ✅ → advisories[].published + history[].date (event=advisory_added)
├── updated_at                        ✅ → advisories[].updated + history[].date (event=advisory_updated, if ≠ published)
├── kind                              ✗  (filter: only "Security" processed)
├── cves[].cve                        ✅ → cve.cve_id + aliases[]  (must start with "CVE-")
└── packages[]/
    ├── product_name                  ✅ → major release (regex "Rocky Linux (\d+)") → purl distro tag
    └── nevra                         ✅ → packages[].name + packages[].ranges[].events[].fixed
                                          (parsed name-epoch:version-release.arch; arch src/nosrc skipped)

Legend: ✅ imported  ✗ not imported
```

## PURL
`pkg:rpm/rocky/<package>?distro=rocky-<major>` — e.g. `pkg:rpm/rocky/curl?distro=rocky-9`

The package PURL carries no version (it is a package identity). The fixed version is
stored in `packages[].ranges[].events[].fixed` as the full NVR (e.g. `7.76.1-26.el9_3.2`,
or `1:3.5.5-4.el9_8` when an epoch is present). The synthetic distro CPE is preserved in
`packages[].vendor_data.cpe` as `cpe:2.3:o:rocky:rocky_linux:<major>:*:*:*:*:*:*:*`.
Both feeds emit the identical PURL/CPE shape, so records from the two feeds merge cleanly.

## State mapping

Both Rocky feeds only list packages that were fixed by an advisory. Every imported
package is therefore emitted with a constant state — neither feed carries a
not-affected / under-investigation / will-not-fix vocabulary.

| Source | `affected_state` | `remediation_state` | `status_raw` |
|---|---|---|---|
| package present in a security RLSA (updateinfo or Apollo) | `affected` | `fixed` | `fixed` |

## Notes
- Rocky Linux rebuilds Red Hat errata: RLSA advisories track the corresponding RHSA. The transforms do not derive an RHSA ID into a structured field; updateinfo reference links (bugzilla/self/other) are stored only as `references[]` entries, and the Apollo feed records no references at all.
- The two feeds are complementary: updateinfo provides the historical bulk plus descriptions and references; Apollo provides the recent tail (titles from `synopsis`, no descriptions, no references).
- Per-CVE deduplication is keyed by `(cve_id, major)`. When the same package PURL appears in more than one advisory for a CVE, the package from the lexicographically higher advisory ID wins.
- Known gaps in coverage: the updateinfo feed is limited to the BaseOS, AppStream, and NFV repos on x86_64. kernel-rt and Cloud Kernel (RXSA) advisories from other repositories are not synced.
- No CVSS scores, no CWEs, no mitigations, no impacts, and no exploit data are available in either feed.
- The previous documentation referenced an Aqua `vuln-list-rocky` third-party mirror; the current ingest uses the official Rocky repodata and the Apollo API.

---

## Schema Coverage

`(U)` = populated by the updateinfo.xml feed, `(A)` = populated by the Apollo feed.

```
LVE Record
├── aliases[]                    ✅  [cve_id] + all RLSA advisory IDs for the CVE/major  (U, A)
├── has_exploit                  ❌  not written — no exploit data in either feed
│
├── cve{}
│   ├── cve_id                   ✅  CVE reference  (U, A) (seed only)
│   ├── status                   ❌  NVD only
│   ├── published               ❌  NVD only
│   ├── updated                 ❌  NVD only
│   ├── epss{}                   ❌  EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ✅  (U) update.title / (A) advisory.synopsis
├── descriptions[]              ✅  (U) update.description  —  ❌ Apollo provides none
├── cvss[]                       ❌  not provided by either feed
├── cwes[]                       ❌  not provided by either feed
├── references[]                 ✅  (U) bugzilla (report) + self/other (advisory/web)  —  ❌ Apollo provides none
│
├── advisories[]
│   ├── @id                      ✅  RLSA-ID  (U: update.id / A: advisory.name)
│   ├── url                      ✅  https://errata.rockylinux.org/<RLSA-ID>
│   ├── published                ✅  (U) issued / (A) published_at
│   ├── updated                  ✅  (U) updated / (A) updated_at
│   └── vendor_data              ❌  not written
│
├── upstream[]                   ❌  not written
│
├── packages[]
│   ├── name                     ✅  (U) package @name / (A) parsed from nevra
│   ├── purl                     ✅  pkg:rpm/rocky/<name>?distro=rocky-<major>  (no version)
│   ├── affected_state           ✅  constant "affected"
│   ├── remediation_state        ✅  constant "fixed"
│   ├── status_raw               ✅  constant "fixed"
│   ├── vex_justification        ❌  not written
│   ├── ranges                   ✅  [{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"<NVR>"}]}]
│   ├── severity                 ✅  advisory severity (mapped)
│   ├── source                   ✅  "rocky"
│   ├── advisory                 ✅  RLSA-ID
│   ├── upstream                 ❌
│   └── vendor_data              ✅  {"cpe": "cpe:2.3:o:rocky:rocky_linux:<major>:..."}
│
├── mitigations[]                ❌  not provided by either feed
├── impacts[]                    ❌  not provided by either feed
├── exploits[]                   ❌  not written
│
└── history[]
    ├── date                     ✅  issued/published_at + updated/updated_at
    ├── event                    ✅  advisory_added / advisory_updated
    ├── source                   ✅  "rocky"
    └── detail                   ✅  RLSA-ID
```
