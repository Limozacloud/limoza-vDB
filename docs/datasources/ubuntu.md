# Ubuntu / Canonical

## OpenVEX
- **URL:** `https://github.com/canonical/ubuntu-security-notices` (sparse clone, `vex/cve/` directory)
- **Official:** Yes — Canonical-maintained
- **Format:** OpenVEX JSON, one file per CVE
- **Local path:** `vex/cve/<year>/CVE-<year>-<id>.json`
- **Sync:** `git pull --ff-only` on each run (shared sparse clone with USN and OSV feeds)
- **Content:** fix status per package per Ubuntu release, fix versions, vulnerability description, alias URLs. One statement per status group; per-arch PURLs included but only `arch=source` is processed. ESM distros are normalized to their base codename.

```
@context                              ✗
@id                                   ✗
author                                ✗
timestamp  (document-level)           ✗
version                               ✗

statements[]/
├── vulnerability/
│   ├── @id                           ✗
│   ├── name                          ✗  (equals CVE ID)
│   ├── description                   ✅ → descriptions[].value  (only statements[0]; fallback if no USN summary)
│   └── aliases[]                     ✅ → references[].url  (http(s), non-NVD, non-ubuntu.com/security/CVE URLs)
│                                          + primary USN-ID extracted if URL contains "ubuntu.com/security/notices/USN-"
├── timestamp                         ✅ → history[].date  (fallback if no USN timestamp)
├── products[]/
│   └── @id  (purl)                   ✅ → packages[].name + packages[].purl + ranges[].events[].fixed
│                                          only arch=source processed; version → ranges only when fixed
│                                          ESM distros: "esm-infra-legacy/trusty" → "trusty"
├── status                            ✅ → packages[].affected_state + packages[].remediation_state
│   (raw value)                            → packages[].status_raw
├── justification                     ✅ → packages[].vex_justification
├── impact_statement                  ✗  (not_affected explanation — not captured)
├── action_statement                  ✗  (affected guidance — not captured)
└── status_notes                      ✗  (not captured)

Legend: ✅ imported  ✗ not imported
```


## USN (Ubuntu Security Notices)
- **URL:** `https://github.com/canonical/ubuntu-security-notices` (sparse clone, `usn/` directory)
- **Official:** Yes — Canonical-maintained
- **Format:** JSON per USN advisory, filename `<id>.json` (e.g. `6765-1.json`)
- **Local path:** `usn/<id>.json`
- **Sync:** `git pull --ff-only` on each run
- **Content:** advisory title, short summary, publish timestamp, CVE list — loaded into memory and joined with the VEX feed (provides titles, descriptions, advisory records, and a CVE→USN reverse index)

```
id                                    ✅ → advisories[].@id  (the USN-ID key, e.g. USN-6765-1)
title                                 ✅ → titles[].value
description  (full text)              ✗  (not imported — prefer isummary/summary)
isummary                              ✗  (not read by the transform)
summary                               ✅ → descriptions[].value  (only when VEX has no description)
timestamp  (Unix int)                 ✅ → advisories[].published + history[].date
cves[]                                ✅ → CVE→USN reverse index (links CVEs not present in VEX aliases)
releases{}                            ✗  (per-release binary package info — not imported)
  └── <codename>/
      ├── binaries{}                  ✗
      └── archs{}                     ✗
          └── <arch>/urls{}           ✗

Legend: ✅ imported  ✗ not imported
```


## OSV (severity enrichment)
- **URL:** `https://github.com/canonical/ubuntu-security-notices` (sparse clone, `osv/cve/` directory)
- **Official:** Yes — Canonical-maintained
- **Format:** OSV JSON per CVE
- **Local path:** `osv/cve/<year>/CVE-<year>-<id>.json`
- **Sync:** `git pull --ff-only` on each run
- **Content:** only the Ubuntu-assigned severity label is read; applied uniformly to every package of the CVE

```
severity[]/
├── type = "Ubuntu"                   ✅ (selects this entry)
└── score                             ✅ → packages[].severity
                                          critical/high/medium/low pass through;
                                          "negligible" → "informational"; others dropped
(all other OSV fields)                ✗

Legend: ✅ imported  ✗ not imported
```

## PURL
`pkg:deb/ubuntu/<name>?distro=<codename>` — e.g. `pkg:deb/ubuntu/xz-utils?distro=jammy`

Built from `arch=source` PURLs in `products[]`. The PURL carries no version (it is a package
identity). Fix versions go into `packages[].ranges[].events[].fixed`. The source release CPE is
preserved in `packages[].vendor_data.cpe` as
`cpe:2.3:o:canonical:ubuntu_linux:<version>:*:*:*:*:*:*:*`.

## State mapping

| OpenVEX `status` | `affected_state` | `remediation_state` | `status_raw` |
|---|---|---|---|
| `fixed` | `affected` | `fixed` | `fixed` |
| `affected` | `affected` | `pending` | `affected` |
| `not_affected` | `not_affected` | `unknown` | `not_affected` |
| `under_investigation` | `unknown` | `unknown` | `under_investigation` |
| (any other) | `unknown` | `unknown` | (raw value) |

`ranges` are populated only when `remediation_state == "fixed"` and a version is present.

## Notes
- All three feeds (VEX, USN, OSV) live in one sparse git clone of `canonical/ubuntu-security-notices`; USN and OSV metadata are loaded into memory before VEX processing — no separate advisory pass.
- Multiple USNs per CVE are possible: the primary comes from the VEX `aliases[]`, additional ones from the USN→CVE reverse index. All are emitted as `advisories[]` and `aliases[]`; the primary USN-ID is attached to packages, titles, descriptions, and references.
- Only `arch=source` PURLs are processed — avoids duplicating the same package per architecture. Duplicate `(name, codename)` pairs are de-duplicated (first statement wins).
- ESM distros are normalized to their base codename (e.g. `esm-infra-legacy/trusty` → `trusty`); a codename not in the known table is skipped.
- No CVSS or CWE in any Ubuntu feed — both must come from NVD.
- `justification` is imported as `vex_justification`; `impact_statement`, `action_statement`, and `status_notes` are present in real data but not imported.

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id, ...USN-IDs from VEX aliases[] + USN→CVE reverse index]
├── has_exploit                  ❌  not written — no exploit data
│
├── cve{}
│   ├── cve_id                   ✅  from filename / call argument  (seed only)
│   ├── status                   ❌  NVD only
│   ├── published               ❌  NVD only
│   ├── updated                  ❌  NVD only
│   ├── epss{}                   ❌  FIRST EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ✅  (USN) usn.title  (advisory_ref = primary USN-ID)
├── descriptions[]              ✅  (VEX) statements[0].vulnerability.description / (USN) usn.summary (fallback)
├── cvss[]                       ❌  not present in any Ubuntu feed
├── cwes[]                       ❌  not present in any Ubuntu feed
├── references[]                 ✅  (VEX) vulnerability.aliases[] (filtered; type advisory if "notices", else web)
│
├── advisories[]
│   ├── @id                      ✅  (USN) USN-ID
│   ├── source                   ✅  "ubuntu"
│   ├── url                      ✅  https://ubuntu.com/security/notices/<USN-ID>
│   ├── published                ✅  (USN) usn.timestamp → ISO 8601
│   ├── updated                  ❌
│   └── vendor_data              ❌
│
├── upstream[]                   ❌  not written
│
├── packages[]
│   ├── name                     ✅  (VEX) name from arch=source purl
│   ├── purl                     ✅  pkg:deb/ubuntu/<name>?distro=<codename>  (no version)
│   ├── affected_state           ✅  derived from VEX status (see State mapping)
│   ├── remediation_state        ✅  derived from VEX status (see State mapping)
│   ├── status_raw               ✅  raw OpenVEX status string
│   ├── vex_justification        ✅  (VEX) statements[].justification
│   ├── ranges                   ✅  [{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"<version>"}]}] when fixed; null otherwise
│   ├── severity                 ✅  (OSV) severity[type=Ubuntu].score (mapped); null if absent
│   ├── source                   ✅  "ubuntu"
│   ├── advisory                 ✅  primary USN-ID  (null if none)
│   ├── upstream                 ❌
│   └── vendor_data              ✅  {"cpe": "cpe:2.3:o:canonical:ubuntu_linux:<version>:*:*:*:*:*:*:*"}
│
├── mitigations[]                ❌  not written
├── impacts[]                    ❌  not written
├── exploits[]                   ❌  not written
│
└── history[]
    ├── date                     ✅  (USN) usn.timestamp / (VEX) earliest statements[].timestamp (fallback)
    ├── event                    ✅  "advisory_added"
    ├── source                   ✅  "ubuntu"
    └── detail                   ✅  USN-ID (or CVE-ID in the fallback case)
```
