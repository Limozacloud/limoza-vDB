# AlmaLinux

## Errata API
- **URL:** `https://errata.almalinux.org/<major>/errata.json`
- **Official:** Yes — AlmaLinux OS Foundation-maintained
- **Format:** JSON (one array of errata objects per major release)
- **Local path:** `<almalinux_errata>/<major>.json` (e.g. `8.json`, `9.json`, `10.json`)
- **Sync:** conditional `HEAD` per major release; the file is re-downloaded only when the `ETag` (or, as a fallback, `Last-Modified`) differs from the stored checkpoint. Major releases synced: 8, 9, 10.
- **Content:** ALSA-* (AlmaLinux Security Advisories) with their CVE references, fixed package NVRs per major release, advisory severity, title, description, issued/updated dates, and bugzilla/RHSA/self reference links. Only errata of `type == "security"` are imported.

```
errata[] (one object per ALSA)/
├── type                              ✗  (filter: only "security" processed)
├── updateinfo_id                     ✅ → advisories[].@id + packages[].advisory + history[].detail + aliases[]
├── severity                          ✅ → packages[].severity (mapped Critical→critical, Important→high, Moderate→medium, Low→low)
├── title                             ✅ → titles[].value
├── description                       ✅ → descriptions[].value
├── issued_date.$date (epoch ms)      ✅ → advisories[].published + history[].date (event=advisory_added)
├── updated_date.$date (epoch ms)     ✅ → advisories[].updated + history[].date (event=advisory_updated, if ≠ published)
├── references[]/
│   ├── [type=cve].id                 ✅ → cve.cve_id + aliases[]  (must start with "CVE-")
│   ├── [type=bugzilla].href          ✅ → references[].url (type=report)
│   ├── [type=rhsa].href              ✅ → references[].url (type=advisory)
│   ├── [type=self].href              ✅ → references[].url (type=advisory)
│   └── (other types)                 ✗
└── pkglist.packages[]/
    ├── name                          ✅ → packages[].name + packages[].purl
    ├── version                       ✅ → packages[].ranges[].events[].fixed (NVR)
    ├── release                       ✅ → packages[].ranges[].events[].fixed (NVR)
    ├── epoch                         ✅ → packages[].ranges[].events[].fixed (prefixed "<epoch>:" when ≠ 0)
    └── arch                          ✗  (per-arch duplicates collapsed by (name,version,release))

Legend: ✅ imported  ✗ not imported
```

## PURL
`pkg:rpm/almalinux/<package>?distro=almalinux-<major>` — e.g. `pkg:rpm/almalinux/curl?distro=almalinux-9`

The package PURL carries no version (it is a package identity). The fixed version is
stored in `packages[].ranges[].events[].fixed` as the full NVR (e.g. `7.76.1-26.el9_3.2`,
or `1:3.5.5-4.el9_8` when an epoch is present). The synthetic distro CPE is preserved in
`packages[].vendor_data.cpe` as `cpe:2.3:o:almalinux:almalinux:<major>:*:*:*:*:*:*:*`.

## State mapping

AlmaLinux errata only list packages that were fixed by an advisory. Every imported
package is therefore emitted with a constant state — the feed carries no
not-affected / under-investigation / will-not-fix vocabulary.

| Errata source | `affected_state` | `remediation_state` | `status_raw` |
|---|---|---|---|
| package present in a security ALSA `pkglist` | `affected` | `fixed` | `fixed` |

## Notes
- AlmaLinux rebuilds Red Hat errata: ALSA advisories track the corresponding RHSA. The `rhsa`-type reference link in each erratum points back to the source RHSA, but the transform does not derive the RHSA ID into a structured field — it is only stored as a `references[]` entry (type=advisory).
- Per-CVE deduplication is keyed by `(cve_id, major)`, so one LVE record is produced per CVE per major release.
- When the same package PURL appears in more than one advisory for a CVE, the package from the lexicographically higher advisory ID wins (treated as the more recent respin).
- No CVSS scores, no CWEs, no mitigations, no impacts, and no exploit data are available in this feed.
- The previous documentation referenced an Aqua `vuln-list-alma` third-party mirror; the current ingest uses the official `errata.almalinux.org` JSON exclusively.

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id] + all ALSA advisory IDs for the CVE/major
├── has_exploit                  ❌  not written — no exploit data in the errata feed
│
├── cve{}
│   ├── cve_id                   ✅  references[type=cve].id  (seed only)
│   ├── status                   ❌  NVD only
│   ├── published               ❌  NVD only
│   ├── updated                 ❌  NVD only
│   ├── epss{}                   ❌  EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ✅  primary advisory title
├── descriptions[]              ✅  primary advisory description
├── cvss[]                       ❌  not provided by the errata feed
├── cwes[]                       ❌  not provided by the errata feed
├── references[]                 ✅  bugzilla (report) + rhsa/self (advisory) links, deduped by URL
│
├── advisories[]
│   ├── @id                      ✅  updateinfo_id (ALSA-YYYY:NNNN)
│   ├── url                      ✅  https://errata.almalinux.org/<major>/<ALSA with ":"→"-">.html
│   ├── published                ✅  issued_date
│   ├── updated                  ✅  updated_date
│   └── vendor_data              ❌  not written
│
├── upstream[]                   ❌  not written
│
├── packages[]
│   ├── name                     ✅  pkglist.packages[].name
│   ├── purl                     ✅  pkg:rpm/almalinux/<name>?distro=almalinux-<major>  (no version)
│   ├── affected_state           ✅  constant "affected"
│   ├── remediation_state        ✅  constant "fixed"
│   ├── status_raw               ✅  constant "fixed"
│   ├── vex_justification        ❌  not written
│   ├── ranges                   ✅  [{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"<NVR>"}]}]
│   ├── severity                 ✅  advisory severity (mapped)
│   ├── source                   ✅  "almalinux"
│   ├── advisory                 ✅  ALSA-ID
│   ├── upstream                 ❌
│   └── vendor_data              ✅  {"cpe": "cpe:2.3:o:almalinux:almalinux:<major>:..."}
│
├── mitigations[]                ❌  not provided by the errata feed
├── impacts[]                    ❌  not provided by the errata feed
├── exploits[]                   ❌  not written
│
└── history[]
    ├── date                     ✅  issued_date / updated_date
    ├── event                    ✅  advisory_added / advisory_updated
    ├── source                   ✅  "almalinux"
    └── detail                   ✅  ALSA-ID
```
