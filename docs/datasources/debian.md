# Debian

## Security Tracker JSON
- **URL:** `https://security-tracker.debian.org/tracker/data/json`
- **Official:** Yes — Debian Security Team-maintained
- **Format:** Single large JSON object (~75 MB), package-keyed → CVE-keyed → release-keyed
- **Local path:** `data.json`
- **Sync:** ETag-based HEAD check; downloads the full file only when the ETag changes
- **Content:** per-package, per-CVE, per-release (buster/bullseye/bookworm/trixie/forky) status, fix version, urgency, and no-DSA reason. The transform inverts the package→CVE nesting and emits one LVE record per CVE.

```
<package_name>/                       (top-level key)
└── <CVE-ID>/                         ✅ → cve.cve_id  (one LVE record per CVE)
    ├── description                   ✅ → descriptions[].value  (first package seen wins)
    ├── scope                         ✗
    ├── debianbug                     ✗
    └── releases/
        └── <codename>/              (only buster/bullseye/bookworm/trixie/forky kept)
            ├── status                ✅ → packages[].affected_state + remediation_state + status_raw
            ├── fixed_version         ✅ → packages[].ranges[].events[].fixed  (when != "0")
            ├── urgency               ✅ → packages[].severity  (low/low**→low, medium→medium, high→high)
            ├── nodsa_reason          ✅ → packages[].vendor_data.nodsa_reason
            ├── nodsa                 ✗
            ├── repositories{}        ✗
            └── (other keys)          ✗

Legend: ✅ imported  ✗ not imported
```

## DSA / DLA advisory lists
- **URL:** `https://salsa.debian.org/security-tracker-team/security-tracker.git` (`data/DSA/list`, `data/DLA/list`)
- **Official:** Yes — Debian Security Team-maintained
- **Format:** Plain-text advisory list (one block per advisory)
- **Local path:** `dsa_list.txt`, `dla_list.txt`
- **Sync:** fetched via `git clone --depth=1 --no-checkout --filter=blob:none` + sparse-checkout on each run (bypasses Salsa proof-of-work)
- **Content:** parsed into `(CVE, codename) → [advisory IDs]`, `advisory ID → date`, and `advisory ID → title`. Used to attach DSA/DLA advisories, titles, and history to the matching CVE records.

```
[<DD Mon YYYY>] (DSA|DLA)-<num>-<num> <title>   advisory header line
├── date                              ✅ → advisories[].published + history[].date
├── advisory ID                       ✅ → advisories[].@id + aliases[]
└── title                             ✅ → titles[].value  (from earliest advisory)
    {CVE-... CVE-...}                  (CVE list line)  ✅ → joins advisory to CVE
        [<codename>] ...              (release line)   ✅ → joins advisory to (CVE, codename) pair

Legend: ✅ imported  ✗ not imported
```

## PURL
`pkg:deb/debian/<package>?distro=<codename>` — e.g. `pkg:deb/debian/curl?distro=bullseye`

The PURL carries no version. Fix versions are stored in `packages[].ranges[].events[].fixed`
(the full Debian version, e.g. `7.74.0-1.3+deb11u10`). The release CPE is preserved in
`packages[].vendor_data.cpe` as `cpe:2.3:o:debian:debian_linux:<major>:*:*:*:*:*:*:*`.

## State mapping

| Tracker `status` | condition | `affected_state` | `remediation_state` | `status_raw` |
|---|---|---|---|---|
| `resolved` | `fixed_version` present and != "0" | `affected` | `fixed` | `resolved` |
| `resolved` | no usable `fixed_version` | `not_affected` | `unknown` | `resolved` |
| `open` | — | `affected` | `pending` | `open` |
| (any other, e.g. `undetermined`) | — | `unknown` | `unknown` | (raw value) |

`ranges` are populated only when a fix version is present (i.e. the `resolved` + fixed case).

## Notes
- Only the five mapped release codenames (buster=10, bullseye=11, bookworm=12, trixie=13, forky=14) are kept; `sid`/`unstable` and unknown codenames are skipped.
- DSA = Debian Security Advisory (stable); DLA = Debian LTS Advisory (community LTS). Both lists are parsed identically and merged.
- A CVE may map to several advisories across releases; they are sorted earliest-first (by date, then ID). The title comes from the earliest advisory that has one, and the package `advisory` field is the first (primary) advisory for that `(CVE, codename)` pair.
- `nodsa_reason` (Debian's explanation for not issuing a dedicated DSA) is preserved verbatim in `vendor_data.nodsa_reason`.
- No CVSS or CWE from Debian — both must come from NVD. Debian `urgency` provides only a coarse severity label.
- A static reference to the per-CVE tracker page is always added: `https://security-tracker.debian.org/tracker/<CVE-ID>` (type `advisory`).

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id, ...DSA/DLA advisory IDs]
├── has_exploit                  ❌  not written — no exploit data
│
├── cve{}
│   ├── cve_id                   ✅  CVE key from tracker JSON  (seed only)
│   ├── status                   ❌  NVD only
│   ├── published               ❌  NVD only
│   ├── updated                  ❌  NVD only
│   ├── epss{}                   ❌  FIRST EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ✅  (DSA/DLA list) advisory title  (advisory_ref = earliest advisory)
├── descriptions[]              ✅  (tracker) per-CVE description
├── cvss[]                       ❌  not present in Debian feeds
├── cwes[]                       ❌  not present in Debian feeds
├── references[]                 ✅  static https://security-tracker.debian.org/tracker/<CVE-ID> (type advisory)
│
├── advisories[]
│   ├── @id                      ✅  (DSA/DLA list) DSA-/DLA-<num>-<num>
│   ├── source                   ✅  "debian"
│   ├── url                      ✅  https://security-tracker.debian.org/tracker/<advisory-id>
│   ├── published                ✅  (DSA/DLA list) advisory date  (null if list had no date)
│   ├── updated                  ❌
│   └── vendor_data              ❌
│
├── upstream[]                   ❌  not written
│
├── packages[]
│   ├── name                     ✅  (tracker) top-level package key
│   ├── purl                     ✅  pkg:deb/debian/<name>?distro=<codename>  (no version)
│   ├── affected_state           ✅  derived from tracker status (see State mapping)
│   ├── remediation_state        ✅  derived from tracker status (see State mapping)
│   ├── status_raw               ✅  raw tracker status ("open"/"resolved"/...)
│   ├── vex_justification        ❌  not written (Debian has no VEX justification vocabulary)
│   ├── ranges                   ✅  [{type:"ECOSYSTEM", events:[{introduced:"0"},{fixed:"<version>"}]}] when fixed; null otherwise
│   ├── severity                 ✅  (tracker) urgency mapped to low/medium/high; null otherwise
│   ├── source                   ✅  "debian"
│   ├── advisory                 ✅  primary (first) DSA/DLA for the (CVE, codename) pair; omitted if none
│   ├── upstream                 ❌
│   └── vendor_data              ✅  {"cpe": "..."}  + {"nodsa_reason": "..."} when present
│
├── mitigations[]                ❌  not written
├── impacts[]                    ❌  not written
├── exploits[]                   ❌  not written
│
└── history[]
    ├── date                     ✅  (DSA/DLA list) advisory date  (only for advisories that have a date)
    ├── event                    ✅  "advisory_added"
    ├── source                   ✅  "debian"
    └── detail                   ✅  advisory ID
```
