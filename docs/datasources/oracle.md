# Oracle Linux

## OVAL
- **URL:** `https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2`
- **Official:** Yes — Oracle-maintained
- **Format:** bzip2-compressed OVAL XML (single combined "all" file)
- **Local path:** `<oracle_oval>/com.oracle.elsa-all.xml` (downloaded as `.xml.bz2`, then decompressed; the `.bz2` is removed)
- **Sync:** conditional `HEAD` on the combined file; re-downloaded only when the `ETag` differs from the stored checkpoint (download retried up to 3 times with backoff). The whole archive is parsed by streaming (`iterparse`) over `<definition class="patch">` elements.
- **Content:** ELSA-* (Oracle Linux Security Advisory) definitions with their CVE references, affected Oracle Linux major versions, fixed package versions (from the OVAL criteria tree), per-CVE CVSS v3 vectors, severity, description, and issued date.

```
oval_definitions/definitions/definition[@class="patch"]/
├── metadata/
│   ├── title                         ✅ → titles[].value; ELSA ID = text before first ":" → advisories[].@id + aliases[] + packages[].advisory
│   ├── reference[@source="CVE"]      ✅ → cve.cve_id + aliases[]  (ref_id must start with "CVE-")
│   ├── description                   ✅ → descriptions[].value
│   ├── affected/platform[]           ✅ → OL major version (regex "Oracle Linux (\d+)") → purl distro tag + CPE
│   └── advisory/
│       ├── severity                  ✅ → packages[].severity + cvss[].severity (Critical→critical, Important→high, Moderate→medium, Low→low)
│       ├── issued[@date]             ✅ → advisories[].published + history[].date (event=advisory_added)
│       ├── cve[@cvss3]               ✅ → cvss[].{score,vector,version}  (parsed "<score>/CVSS:3.x/..."; matched to the CVE by element text)
│       └── (rights / other)          ✗
└── criteria/ (recursive)/
    └── criterion[@comment="<pkg> is earlier than <evr>"]  ✅ → packages[].name + packages[].ranges[].events[].fixed
                                          (epoch stripped from version; comments containing "signed with" skipped)

Legend: ✅ imported  ✗ not imported
```

## PURL
`pkg:rpm/oracle/<package>?distro=ol<major>` — e.g. `pkg:rpm/oracle/curl?distro=ol9`

The package PURL carries no version (it is a package identity). The fixed version is
stored in `packages[].ranges[].events[].fixed`, taken from the OVAL criterion
"is earlier than" comparand with any leading `<epoch>:` stripped. The synthetic distro
CPE is preserved in `packages[].vendor_data.cpe` as
`cpe:2.3:o:oracle:linux:<major>:*:*:*:*:*:*:*`. Each fixed package is expanded across
every affected OL major version listed in the definition (one package row per
`(name, major)`).

## State mapping

OVAL `patch` definitions describe the condition under which a system is missing a fix,
i.e. they enumerate fixed packages. Every imported package is therefore emitted with a
constant state — the OVAL feed carries no not-affected / under-investigation /
will-not-fix vocabulary.

| OVAL source | `affected_state` | `remediation_state` | `status_raw` |
|---|---|---|---|
| package criterion in an ELSA `patch` definition | `affected` | `fixed` | `fixed` |

## Notes
- Oracle Linux rebuilds Red Hat errata: ELSA advisories track the corresponding RHSA. The OVAL feed does not expose the source RHSA ID, so no RHSA cross-reference is recorded.
- The ELSA ID is parsed from the title prefix (text before the first `:`). When a title has no `:`, the definition produces no advisory/`@id` and the package `advisory` field is null.
- The combined OVAL file covers all currently maintained majors (e.g. Oracle Linux 7, 8, 9, 10); the actual majors are derived per-definition from the `affected/platform` entries.
- Unlike AlmaLinux and Rocky, this feed **does** carry per-CVE CVSS v3 data (`cvss[]`).
- The advisory has only an `issued` date — there is no `updated`/current-release date, so `advisories[].updated` and `advisory_updated` history events are never written.
- Oracle publishes both regular and UEK (Unbreakable Enterprise Kernel) advisories; both appear in the combined OVAL file and are processed identically (kernel-uek packages are emitted as ordinary packages).
- No CWEs, no mitigations, no impacts, and no exploit data are available in this feed.

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id] + ELSA-ID (when present)
├── has_exploit                  ❌  not written — no exploit data in OVAL
│
├── cve{}
│   ├── cve_id                   ✅  reference[source=CVE].ref_id  (seed only)
│   ├── status                   ❌  NVD only
│   ├── published               ❌  NVD only
│   ├── updated                 ❌  NVD only
│   ├── epss{}                   ❌  EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ✅  metadata.title
├── descriptions[]              ✅  metadata.description
├── cvss[]                       ✅  advisory.cve[@cvss3] → {score, vector, version, severity}  (CVSS v3 only)
├── cwes[]                       ❌  not provided by OVAL
├── references[]                 ✅  https://linux.oracle.com/errata/<ELSA-ID>.html (type=advisory)
│
├── advisories[]
│   ├── @id                      ✅  ELSA-ID (parsed from title prefix)
│   ├── url                      ✅  https://linux.oracle.com/errata/<ELSA-ID>.html
│   ├── published                ✅  advisory.issued.date
│   ├── updated                  ❌  not provided by OVAL
│   └── vendor_data              ❌  not written
│
├── upstream[]                   ❌  not written
│
├── packages[]
│   ├── name                     ✅  criterion "is earlier than" package name
│   ├── purl                     ✅  pkg:rpm/oracle/<name>?distro=ol<major>  (no version)
│   ├── affected_state           ✅  constant "affected"
│   ├── remediation_state        ✅  constant "fixed"
│   ├── status_raw               ✅  constant "fixed"
│   ├── vex_justification        ❌  not written
│   ├── ranges                   ✅  [{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"<EVR, epoch stripped>"}]}]
│   ├── severity                 ✅  advisory.severity (mapped)
│   ├── source                   ✅  "oracle"
│   ├── advisory                 ✅  ELSA-ID
│   ├── upstream                 ❌
│   └── vendor_data              ✅  {"cpe": "cpe:2.3:o:oracle:linux:<major>:..."}
│
├── mitigations[]                ❌  not provided by OVAL
├── impacts[]                    ❌  not provided by OVAL
├── exploits[]                   ❌  not written
│
└── history[]
    ├── date                     ✅  advisory.issued.date
    ├── event                    ✅  advisory_added  (advisory_updated never written — no updated date)
    ├── source                   ✅  "oracle"
    └── detail                   ✅  ELSA-ID
```
