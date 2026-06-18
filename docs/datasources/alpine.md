# Alpine Linux

## secdb
- **URL:** `https://secdb.alpinelinux.org/`
- **Official:** Yes — Alpine Linux-maintained
- **Format:** JSON, one file per release per repository
- **Local path:** `<version>/<repo>.json` — e.g. `v3.20/main.json`, `v3.21/community.json`, `edge/main.json`
- **Sync:** timestamp-based — fetches `/last-update` and re-downloads all files only when the timestamp changes. Releases `v3.14`–`v3.24` and `edge`, repos `main` and `community`.
- **Content:** per-release, per-repo list of packages with a `secfixes` map (fix version → list of CVE IDs fixed in that version). The transform emits one LVE record per CVE per file.

```
distroversion                         ✅ → packages[].vendor_data.cpe (version part) + PURL ?distro=
apkurl                                ✗
reponame                              ✗
urlprefix                             ✗
archs[]                               ✗
packages[]/
└── pkg/
    ├── name                          ✅ → packages[].name + packages[].purl
    └── secfixes/
        └── <fix_version>/            ✅ → packages[].ranges[].events[].fixed  (when != "0")
            └── [CVE-ID ...]          ✅ → cve.cve_id  (one record per CVE; space-separated IDs split)
    (any other pkg keys, incl. advisories)  ✗

Legend: ✅ imported  ✗ not imported
```

## PURL
`pkg:apk/alpine/<package>?distro=<version>` — e.g. `pkg:apk/alpine/curl?distro=v3.20`

The PURL carries no version and the `distro` qualifier keeps the leading `v` (e.g. `v3.20`,
`edge`). Fix versions are stored in `packages[].ranges[].events[].fixed`. The release CPE is
preserved in `packages[].vendor_data.cpe` as
`cpe:2.3:o:alpinelinux:alpine_linux:<version>:*:*:*:*:*:*:*` (the leading `v` is stripped here, so
`v3.20` → `3.20`; `edge` is kept as-is).

## State mapping

| secdb `secfixes` key | `affected_state` | `remediation_state` | `status_raw` |
|---|---|---|---|
| version != "0" | `affected` | `fixed` | `<fix_version>` |
| `"0"` | `not_affected` | `unknown` | `0` |

The special key `"0"` is Alpine's convention for "this CVE does not affect / was never present in
this package", hence `not_affected`. `ranges` are populated only for real fix versions.

## Notes
- Only IDs matching `CVE-YYYY-NNNN` are kept; a single `secfixes` list entry may contain several space-separated CVE IDs, which are split into individual records.
- Alpine ships upstream package versions directly (no backporting), so the secdb fix version is effectively the upstream fix version.
- secdb carries no severity, no CVSS, no description, no advisory text, and no advisory IDs in the imported data — the `pkg.advisories` field (present in some entries) is **not** read by the transform. CVSS, CWE, severity, titles, and descriptions must come from other sources (e.g. NVD).
- Absence from secdb is **not** `not_affected` — it simply means Alpine's stance is unknown.
- Repos: `main` (officially supported) and `community`; `edge` is the rolling development branch.

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id]
├── has_exploit                  ❌  not written — no exploit data
│
├── cve{}
│   ├── cve_id                   ✅  from secfixes CVE list  (seed only)
│   ├── status                   ❌  NVD only
│   ├── published               ❌  NVD only
│   ├── updated                  ❌  NVD only
│   ├── epss{}                   ❌  FIRST EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ❌  not present in secdb
├── descriptions[]              ❌  not present in secdb
├── cvss[]                       ❌  not present in secdb
├── cwes[]                       ❌  not present in secdb
├── references[]                 ❌  not written
│
├── advisories[]                 ❌  not written (pkg.advisories not read)
│
├── upstream[]                   ❌  not written
│
├── packages[]
│   ├── name                     ✅  pkg.name
│   ├── purl                     ✅  pkg:apk/alpine/<name>?distro=<version>  (no version)
│   ├── affected_state           ✅  derived from secfixes key (see State mapping)
│   ├── remediation_state        ✅  derived from secfixes key (see State mapping)
│   ├── status_raw               ✅  "0" for not_affected, else the fix version
│   ├── vex_justification        ❌  not written
│   ├── ranges                   ✅  [{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"<version>"}]}] when fixed; null otherwise
│   ├── severity                 ❌  not present in secdb
│   ├── source                   ✅  "alpine"
│   ├── advisory                 ❌  not written
│   ├── upstream                 ❌
│   └── vendor_data              ✅  {"cpe": "cpe:2.3:o:alpinelinux:alpine_linux:<version>:*:*:*:*:*:*:*"}
│
├── mitigations[]                ❌  not written
├── impacts[]                    ❌  not written
├── exploits[]                   ❌  not written
│
└── history[]                    ❌  not written (secdb has no dates)
```
