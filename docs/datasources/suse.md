# SUSE

## CSAF-VEX
- **URL:** `https://ftp.suse.com/pub/projects/security/csaf-vex/`
- **Official:** Yes — SUSE-maintained
- **Format:** CSAF 2.0 JSON (VEX profile), one file per CVE, flat directory (no year subdirs)
- **Local path:** `cve-<year>-<id>.json`
- **Sync:** full archive (`csaf-vex.tar.bz2`, ~377 MB) on first run, incremental via `changes.csv` afterwards
- **Content:** affected products and fix state per SUSE/openSUSE release, fix versions, severity, CVSS scores, description, references. The description note may embed an `Impact Summary:` paragraph that is lifted into `impacts[]`. Advisory IDs are **not** embedded in the VEX — they come from `adv_map.json` (built during the advisory sync).

```
document/
├── aggregate_severity/
│   ├── text                          ✅ → packages[].severity  (critical/important/moderate/low → critical/high/medium/low)
│   └── namespace                     ✗
├── tracking/
│   ├── id                            ✗
│   ├── initial_release_date          ⊃  covered by CSAF-Advisories
│   ├── current_release_date          ⊃  covered by CSAF-Advisories
│   ├── status                        ✗
│   ├── version                       ✗
│   ├── generator/                    ✗
│   └── revision_history[]/
│       ├── date                      ✅ → history[].date
│       ├── number                    ✅ → history[].event (1=vex_published, else vex_updated)
│       └── summary                   ✅ → history[].detail ("revision <n>: <summary>")
├── title                             ✗  (always "SUSE CVE <CVE-ID>", not useful)
├── notes[]/                          ✗  (see vulnerabilities[].notes)
├── references[]/                     ✗
├── publisher/                        ✗
├── distribution/                     ✗
├── lang                              ✗
└── category / csaf_version           ✗

product_tree/
├── branches[category=product_name]/
│   ├── product.product_id                          → platform key (e.g. "SUSE Linux Enterprise Server 16.0")
│   └── product.product_identification_helper.cpe  ✅ → packages[].vendor_data.cpe + used to build PURL distro
└── relationships / other branch categories         ✗
   (compound product_ids "platform:pkg-version" are split directly; the product_name → cpe map
    is the only product_tree structure consumed)

vulnerabilities[0]/                   (only the first vulnerability object is read)
├── cve                               ✅ → cve.cve_id  (seed only) + aliases[]
├── title                             ✗  (always equals cve_id)
├── cwe/                              ✗  not present in SUSE VEX
├── ids[]/                            ✗
├── notes[]/
│   └── [category=description|general].text  ✅ → descriptions[].value
│       └── "Impact Summary: <text>"   ✅ → impacts[].value  (regex-extracted from the same note)
├── scores[]/
│   └── cvss_v31|cvss_v30|cvss_v3|cvss_v2  (first present key per entry)
│       ├── baseScore                 ✅ → cvss[].score   (0.0 valid; entry skipped if score null or vector missing)
│       ├── vectorString              ✅ → cvss[].vector
│       ├── version (from key)        ✅ → cvss[].version (v31/v3→3.1, v30→3.0, v2→2.0)
│       ├── baseSeverity              ✅ → cvss[].severity (lowercased)
│       └── products                  ✗
├── references[]/
│   ├── url                           ✅ → references[].url  (only http(s); deduped)
│   ├── category                      ✅ → references[].type  (self→advisory; bugzilla→report; github blob/commit/pull/patch→patch; github advisories→advisory; else web)
│   └── summary                       ✗
├── remediations[]/
│   ├── [category=vendor_fix]
│   │   ├── product_ids (platform part)  ✅ → packages[].purl  (via product_tree CPE lookup)
│   │   └── product_ids (version part)   ✅ → packages[].ranges[].events[].fixed
│   ├── [category=none_available]        ✅ → known_affected pkg: affected_state=affected, remediation_state=none
│   ├── [category=no_fix_planned]        ✅ → known_affected pkg: affected_state=affected, remediation_state=will_not_fix
│   ├── [category=fix_deferred]          ✅ → known_affected pkg: affected_state=affected, remediation_state=pending
│   ├── [category=workaround]            ✅ → known_affected pkg: affected_state=affected, remediation_state=pending
│   ├── url                              ✗  not present
│   └── details                         ✗  (not mapped to mitigations[])
├── product_status/
│   ├── recommended                  ✅ → packages: affected_state=affected, remediation_state=fixed
│   ├── first_fixed                  ✅ → packages: affected_state=affected, remediation_state=fixed
│   ├── known_affected               ✅ → packages: state from matching remediation category (default affected/pending)
│   ├── under_investigation          ✅ → packages: affected_state=unknown, remediation_state=unknown
│   └── (no known_not_affected emitted)
└── threats[]/                        ✗

adv_map.json/  (external, built during advisory sync)
└── {CVE-ID}: {advisory_id: [platforms]}  ✅ → advisories[].@id + aliases[] + packages[].advisory (matched by platform)

Legend: ✅ imported  ⊃ covered by CSAF-Advisories  ✗ not imported
```


## CSAF-Advisories
- **URL:** `https://ftp.suse.com/pub/projects/security/csaf/`
- **Official:** Yes — SUSE-maintained
- **Format:** CSAF 2.0 JSON, one file per advisory (SUSE-SU-*, openSUSE-SU-*, SUSE-OU-*, openSUSE-RU-*, ...)
- **Local path:** `advisories/<advisory-slug>.json` (saved during advisory map sync)
- **Sync:** full pass over `index.txt` on first run, incremental via `changes.csv` afterwards
- **Content:** per-advisory tracking dates and advisory-level title — populates `advisories[].published`, `advisories[].updated`, `titles[]`, and `history[]` per advisory. The sync also derives `adv_map.json` (CVE → advisory → affected platforms) from each advisory's `product_status.recommended` / `fixed`.

```
document/
├── tracking/
│   ├── id                            ✅ → advisories[].@id  (also the adv_map key)
│   ├── initial_release_date          ✅ → advisories[].published
│   ├── current_release_date          ✅ → advisories[].updated
│   ├── status / version / generator  ✗
│   └── revision_history[]/
│       ├── date                      ✅ → history[].date
│       ├── number                    ✅ → history[].event (1=advisory_added, else advisory_updated)
│       └── summary                   ✅ → history[].detail ("<adv_id> revision <n>: <summary>")
├── title                             ✅ → titles[].value  (advisory_ref = advisory ID)
├── aggregate_severity/               ⊂  covered by VEX
├── notes[] / references[]            ⊂  covered by VEX  (references) / ✗ (notes)
├── publisher / distribution / lang   ✗
└── category / csaf_version           ✗

product_tree/                         ✗  (advisory file only used for dates + title + adv_map)

vulnerabilities[]/
├── cve                               ✅ → used to key the per-CVE partial record (and adv_map)
│   └── product_status.recommended/fixed  ✅ → adv_map platforms (sync-time only)
└── ...                               ⊂  covered by VEX

Legend: ✅ imported  ⊂ covered by VEX  ✗ not imported
```

## PURL
`pkg:rpm/suse/<name>?distro=<distro>` — the distro qualifier is derived from the platform CPE
(`cpe:/o:suse:sles:15:sp5` → `sles-15-sp5`), e.g. `pkg:rpm/suse/busybox?distro=sles-15-sp7`.

The package PURL carries no version (it is a package identity). Fixed versions are stored in
`packages[].ranges[].events[].fixed`. The source platform CPE is preserved in
`packages[].vendor_data.cpe`. A package is deduplicated by `(name, cpe)`; the first state
encountered (fixed → known_affected → under_investigation) wins.

## State mapping

| VEX source | `affected_state` | `remediation_state` | `status_raw` |
|---|---|---|---|
| `remediations[vendor_fix]` | `affected` | `fixed` | `fixed` |
| `product_status.recommended` | `affected` | `fixed` | `fixed` |
| `product_status.first_fixed` | `affected` | `fixed` | `fixed` |
| `product_status.known_affected` + `remediations[none_available]` | `affected` | `none` | `none_available` |
| `product_status.known_affected` + `remediations[no_fix_planned]` | `affected` | `will_not_fix` | `no_fix_planned` |
| `product_status.known_affected` + `remediations[fix_deferred]` | `affected` | `pending` | `fix_deferred` |
| `product_status.known_affected` + `remediations[workaround]` | `affected` | `pending` | `workaround` |
| `product_status.known_affected` (no matching remediation) | `affected` | `pending` | `known_affected` |
| `product_status.under_investigation` | `unknown` | `unknown` | `under_investigation` |

## Notes
- Advisory IDs (SUSE-SU-*, openSUSE-SU-*, SUSE-OU-*, openSUSE-RU-*) are not embedded in the VEX — they come from `adv_map.json`, which is built during the advisory sync by scanning each advisory's `product_status.recommended` / `fixed` for affected platforms.
- `recommended` and `first_fixed` both mean fixed; `first_fixed` marks the earliest distro to ship the patch.
- `packages[].advisory` is set only for fixed packages whose platform matches an entry in `adv_map.json`; it is `null` for `known_affected` / `under_investigation`.
- Only `vulnerabilities[0]` is processed per VEX file (SUSE VEX files carry a single CVE).
- The VEX `document.title` ("SUSE CVE <CVE-ID>") is intentionally not imported; titles come from advisory files only.
- The transform returns `None` (record skipped) when there are no vulnerabilities or no resolvable packages.
- `cwes`, `mitigations`, `notices`, `upstream`, and `exploits` are always emitted empty for this source. SUSE VEX `remediations[].details` are present but **not** mapped to `mitigations[]`.
- The package-name/version split treats plain trailing digits (`-3`, `-32bit`) as part of the name; only a segment beginning with a digit and containing a dot is treated as the version.

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  (VEX) [vulnerabilities[0].cve, ...advisory IDs from adv_map.json]
├── has_exploit                  ❌  not written — no exploit data in SUSE VEX
│
├── cve{}
│   ├── cve_id                   ✅  (VEX) vulnerabilities[0].cve  (seed only — {"cve_id": ...})
│   ├── status                   ❌  NVD only
│   ├── published                ❌  NVD only
│   ├── updated                  ❌  NVD only
│   ├── epss{}                   ❌  FIRST EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ✅  (Advisory) document.title  (advisory_ref = advisory ID)
│                                    note: VEX document.title not imported
├── descriptions[]              ✅  (VEX) vulnerabilities[0].notes[description|general].text (advisory_ref = "csaf_vex:<cve_id>")
├── cvss[]                       ✅  (VEX) vulnerabilities[0].scores[].cvss_v3x.*  (advisory null)
├── cwes[]                       ❌  not present in SUSE VEX (emitted empty)
├── references[]                 ✅  (VEX) vulnerabilities[0].references[].{url,category}  (advisory null)
│
├── advisories[]
│   ├── @id                      ✅  (VEX) adv_map.json key → SUSE-SU-YYYY:NNNN-N / openSUSE-SU-... etc.
│   ├── source                   ✅  "suse"
│   ├── url                      ✅  https://www.suse.com/support/update/announcement/<slug>/
│   ├── published                ✅  (Advisory) document.tracking.initial_release_date
│   ├── updated                  ✅  (Advisory) document.tracking.current_release_date
│   └── vendor_data              ❌
│
├── upstream[]                   ❌  not written (emitted empty)
│
├── packages[]
│   ├── name                     ✅  package name parsed from compound product_id
│   ├── purl                     ✅  pkg:rpm/suse/<name>?distro=<from_cpe>  (no version)
│   ├── affected_state           ✅  derived from product_status / remediations (see State mapping)
│   ├── remediation_state        ✅  derived from product_status / remediations (see State mapping)
│   ├── status_raw               ✅  raw status / remediation category
│   ├── vex_justification        ❌  not written (SUSE VEX has no flags[])
│   ├── ranges                   ✅  [{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"<version>"}]}] for fixed; null otherwise
│   ├── severity                 ✅  document.aggregate_severity.text (mapped)
│   ├── source                   ✅  "suse"
│   ├── advisory                 ✅  advisory ID via adv_map platform match (fixed packages only); null otherwise
│   ├── upstream                 ❌
│   └── vendor_data              ✅  {"cpe": "<platform_cpe>"}
│
├── mitigations[]                ❌  not written (emitted empty) — remediations[].details not mapped
├── impacts[]                    ✅  "Impact Summary:" paragraph extracted from the description note (advisory_ref = "csaf_vex:<cve_id>")
├── exploits[]                   ❌  not written (emitted empty)
│
└── history[]
    ├── date                     ✅  (VEX) revision_history[].date / (Advisory) revision_history[].date
    ├── event                    ✅  vex_published / vex_updated / advisory_added / advisory_updated
    ├── source                   ✅  "suse"
    └── detail                   ✅  revision number + summary (advisory id prefixed for advisory history)
```
