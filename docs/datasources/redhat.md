# Red Hat

## CSAF-VEX
- **URL:** `https://security.access.redhat.com/data/csaf/v2/vex`
- **Official:** Yes — Red Hat-maintained
- **Format:** CSAF 2.0 JSON (VEX profile), one file per CVE
- **Local path:** `vex/<year>/cve-<year>-<id>.json`
- **Sync:** full archive (`csaf_vex_YYYY-MM-DD.tar.zst`) on first run, incremental via `changes.csv` afterwards
- **Content:** affected products and fix status per RHEL release, fix versions, severity, CVSS scores, CWE, references, mitigations



```
document/
├── aggregate_severity/
│   ├── text                          ✅ → packages[].severity
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
│       ├── number                    ✅ → history[].event (1=vex_published, 2+=vex_updated) + history[].detail
│       └── summary                   ✅ → history[].detail
├── title                             ✗
├── notes[]/                          ✗
├── references[]/                     ✗
├── publisher/                        ✗
├── distribution/                     ✗
├── lang                              ✗
└── category / csaf_version           ✗

product_tree/
├── branches[].product.product_identification_helper.cpe  ✅ → packages[].purl + packages[].vendor_data.cpe
└── relationships[]                   ✗

vulnerabilities[]/
├── cve                               ✅ → cve.cve_id
├── title                             ✅ → titles[].value
├── cwe/
│   ├── id                            ✅ → cwes[].id
│   └── name                          ✅ → cwes[].name
├── notes[]/
│   ├── [category=description|general].text  ✅ → descriptions[].value
│   └── [category=other].text         ✅ → impacts[].value  (vendor statement)
├── scores[]/
│   ├── cvss_v3.baseScore             ✅ → cvss[].score
│   ├── cvss_v3.vectorString          ✅ → cvss[].vector
│   ├── cvss_v3.version               ✅ → cvss[].version
│   ├── cvss_v3.baseSeverity          ✅ → cvss[].severity
│   ├── cvss_v3.attack*/impact*/...   ✗
│   └── products                      ✗
├── references[]/
│   ├── url                           ✅ → references[].url
│   ├── category                      ✅ → references[].type
│   └── summary                       ✗
├── remediations[]/
│   ├── [category=vendor_fix]
│   │   ├── url                        ✅ → advisories[].@id + advisories[].url
│   │   ├── date                       ✅ → advisories[].published + history[].date
│   │   ├── product_ids (name part)    ✅ → packages[].name + packages[].purl
│   │   └── product_ids (NVR version)  ✅ → packages[].ranges[].events[].fixed
│   ├── [category=workaround|mitigation].details  ✅ → mitigations[].value
│   └── [category=none_available|no_fix_planned|fix_deferred]  ✅ → packages[].remediation_state
├── product_status/
│   ├── known_not_affected            ✅ → packages[].affected_state = not_affected
│   ├── known_affected                ✅ → packages[].affected_state + remediation_state
│   ├── fixed                         ✗
│   └── under_investigation           ✅ → packages[].affected_state = unknown
├── threats[]/
│   ├── [category=impact].details     ✅ → impacts[].value  (fallback when no statement note)
│   └── product_ids                   ✗
├── flags[]/
│   ├── label                         ✅ → packages[].vex_justification
│   └── product_ids                   ✅ → mapped to the matching package
├── ids[]/                            ✗
├── acknowledgments[]/                ✗
├── discovery_date                    ✗
└── release_date                      ✗

Legend: ✅ imported  ⊃ covered by CSAF-Advisories  ✗ not imported
```


## CSAF-Advisories
- **URL:** `https://security.access.redhat.com/data/csaf/v2/advisories`
- **Official:** Yes — Red Hat-maintained
- **Format:** CSAF 2.0 JSON (CSAF profile), one file per RHSA/RHBA/RHEA advisory
- **Local path:** `advisories/<year>/rhsa-<year>_<id>.json`
- **Sync:** full archive (`csaf_advisories_YYYY-MM-DD.tar.zst`) on first run, incremental via `changes.csv` afterwards
- **Content:** per-advisory tracking dates (`initial_release_date`, `current_release_date`) and advisory-level title — used to populate `lve_advisories.published`, `lve_advisories.updated`, and `lve_titles` per RHSA

```
document/
├── tracking/
│   ├── id                            ✅ → advisories[].@id
│   ├── initial_release_date          ✅ → advisories[].published
│   ├── current_release_date          ✅ → advisories[].updated
│   ├── status                        ✗
│   ├── version                       ✗
│   ├── generator/                    ✗
│   └── revision_history[]/
│       ├── date                          ✅ → history[].date
│       ├── number                        ✅ → history[].event (1=advisory_added, 2+=advisory_updated) + history[].detail
│       └── summary                       ✅ → history[].detail
├── title                             ✅ → titles[].value  (advisory_ref = RHSA-ID)
├── aggregate_severity/               ⊂  covered by VEX
├── notes[]/                          ✗
├── references[]/                     ⊂  covered by VEX
├── publisher/                        ✗
├── distribution/                     ✗
├── lang                              ✗
└── category / csaf_version           ✗

product_tree/                         ⊂  covered by VEX

vulnerabilities[]/
├── cve                               ⊂  covered by VEX
├── title                             ⊂  covered by VEX
├── cwe/                              ⊂  covered by VEX
├── notes[]/                          ⊂  covered by VEX
├── scores[]/                         ⊂  covered by VEX
├── references[]/                     ⊂  covered by VEX
├── remediations[]/
│   ├── category / url / date / product_ids  ⊂  covered by VEX
│   └── restart_required.category     ✅ → advisories[].vendor_data.reboot_required (true if "machine")
├── product_status/                   ⊂  covered by VEX
├── threats[]/
│   ├── category / details            ⊂  covered by VEX
│   └── date                          ✗
├── flags[]/                          ⊂  covered by VEX
├── ids[]/                            ⊂  covered by VEX
├── acknowledgments[]/                ⊂  covered by VEX
├── discovery_date                    ⊂  covered by VEX
└── release_date                      ⊂  covered by VEX

Legend: ✅ imported  ⊂ covered by VEX  ✗ not imported
```

## PURL
`pkg:rpm/redhat/<package>?distro=el<major>` — e.g. `pkg:rpm/redhat/curl?distro=el9`

The package PURL carries no version (it is a package identity). Fixed versions are
stored in `packages[].ranges[].events[].fixed` as the full NVR (e.g.
`0:7.76.1-26.el9_3.2`). The source CPE is preserved in `packages[].vendor_data.cpe`.

## State mapping

| CSAF source | `affected_state` | `remediation_state` | `status_raw` |
|---|---|---|---|
| `remediations[vendor_fix]` | `affected` | `fixed` | `fixed` |
| `product_status.known_not_affected` | `not_affected` | `unknown` | `known_not_affected` |
| `product_status.under_investigation` | `unknown` | `unknown` | `under_investigation` |
| `remediations[none_available]` | `affected` | `none` | (category) |
| `remediations[no_fix_planned]` | `affected` | `will_not_fix` | (category) |
| `remediations[fix_deferred]` | `affected` | `pending` | (category) |
| `product_status.known_affected` (default) | `affected` | `pending` | `known_affected` |

## Notes
- RHSA advisories are the reference for AlmaLinux and Rocky Linux (their errata rebuild Red Hat fixes)
- Advisory types: RHSA = security, RHBA = bugfix (no CVE), RHEA = enhancement (no CVE) — only RHSA relevant for CVE tracking
- `vex_justification` is populated from `flags[].label` when the product is marked not affected

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  (VEX) [vulnerabilities[].cve, ...RHSA-IDs from remediations[].url]
├── has_exploit                  ❌  not written — no exploit data in CSAF
│
├── cve{}
│   ├── cve_id                   ✅  (VEX) vulnerabilities[].cve  (seed only — not overwritten if already set)
│   ├── status                   ❌  NVD only
│   ├── published                ❌  NVD only
│   ├── updated                  ❌  NVD only
│   ├── epss{}                   ❌  EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ✅  (VEX) vulnerabilities[].title / (Advisory) document.title
├── descriptions[]              ✅  (VEX) vulnerabilities[].notes[description|general].text
├── cvss[]                       ✅  (VEX) vulnerabilities[].scores[].cvss_v3.*
├── cwes[]                       ✅  (VEX) vulnerabilities[].cwe.{id,name}
├── references[]                 ✅  (VEX) vulnerabilities[].references[].{url,category}
│
├── advisories[]
│   ├── @id                      ✅  (VEX) remediations[].url → RHSA-YYYY:NNNN
│   ├── url                      ✅  (VEX) https://access.redhat.com/errata/<RHSA>
│   ├── published                ✅  (VEX) remediations[].date / (Advisory) initial_release_date (authoritative)
│   ├── updated                  ✅  (Advisory) current_release_date
│   └── vendor_data              ✅  (Advisory) {"reboot_required": true} when restart_required.category = "machine"
│
├── upstream[]                   ❌  not written — Red Hat tracks downstream RPMs only
│
├── packages[]
│   ├── name                     ✅  package name parsed from NVR
│   ├── purl                     ✅  pkg:rpm/redhat/<name>?distro=el<N>  (no version)
│   ├── affected_state           ✅  derived from product_status / remediations (see State mapping)
│   ├── remediation_state        ✅  derived from product_status / remediations (see State mapping)
│   ├── status_raw               ✅  raw CSAF status / remediation category
│   ├── vex_justification        ✅  flags[].label  (only for not_affected)
│   ├── ranges                   ✅  [{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"<NVR>"}]}] for fixed; null otherwise
│   ├── severity                 ✅  document.aggregate_severity.text
│   ├── source                   ✅  "redhat"
│   ├── advisory                 ✅  RHSA-ID for fixed packages; null otherwise
│   ├── upstream                 ❌
│   └── vendor_data              ✅  {"cpe": "<cpe22>"}
│
├── mitigations[]                ✅  remediations[workaround|mitigation].details
├── impacts[]                    ✅  notes[other].text (statement) or threats[impact].details
├── exploits[]                   ❌  not written — no exploit data in CSAF
│
└── history[]
    ├── date                     ✅  (VEX) revision_history[].date + remediations[].date / (Advisory) revision_history[].date
    ├── event                    ✅  vex_published / vex_updated / advisory_added / advisory_updated
    ├── source                   ✅  "redhat"
    └── detail                   ✅  RHSA-ID and/or revision summary
```
