# CISA KEV (Known Exploited Vulnerabilities)

Enrichment-only source. It populates a single sub-object — `cve.kev{}` — and
contributes nothing else to the LVE record.

## KEV JSON Feed
- **URL:** `https://github.com/cisagov/kev-data` (file: `known_exploited_vulnerabilities.json`)
- **Official:** Yes — CISA (US federal)-maintained
- **Format:** JSON
- **Local path:** `repo/` (shallow git checkout) → reduced to `kev_index.json` (`{cve_id: {...}}`)
- **Sync:** shallow clone (`--depth=1`) on first run, `git pull --ff-only` afterwards; the JSON is then flattened into `kev_index.json`
- **Content:** CVEs confirmed to be actively exploited in the wild, with CISA remediation guidance and ransomware-campaign association

## Field mapping

The sync step extracts many fields into `kev_index.json`, but the transform writes
only four of them into `cve.kev{}`. The remaining indexed fields
(`vendor_project`, `product`, `vulnerability_name`, `short_description`, `notes`,
`cwes`) are **not** consumed by the transform.

```
known_exploited_vulnerabilities.json
└── vulnerabilities[]/
    ├── cveID                          ✅ → aliases[0] + cve.cve_id
    ├── dateAdded                      ✅ → cve.kev.date_added
    ├── dueDate                        ✅ → cve.kev.due_date
    ├── knownRansomwareCampaignUse     ✅ → cve.kev.known_ransomware  (see Notes — coerced to bool)
    ├── requiredAction                 ✅ → cve.kev.required_action
    ├── vendorProject                  ✗  (indexed by sync, not written)
    ├── product                        ✗  (indexed by sync, not written)
    ├── vulnerabilityName              ✗  (indexed by sync, not written)
    ├── shortDescription               ✗  (indexed by sync, not written)
    ├── notes                          ✗  (indexed by sync, not written)
    └── cwes                           ✗  (indexed by sync, not written)

Legend: ✅ imported  ✗ not imported
```

## Notes
- Pure enrichment: no titles, descriptions, CVSS, CWEs, references, advisories, or packages are written, despite some of that data being present in the feed.
- **`known_ransomware` coercion quirk:** when the value is a string (CISA emits `"Known"` / `"Unknown"`), the transform computes `value.lower() not in ("no", "false", "")`. This means `"Unknown"` evaluates to **`true`**, the same as `"Known"`. Only the literal strings `"no"`, `"false"`, and `""` map to `false`. Treat the boolean as "ransomware field present and non-empty" rather than a strict Known/Unknown flag.
- `cve.cve_id` is written as a seed only — not authoritative and not overwritten if already set.
- KEV presence is a hard escalation signal regardless of CVSS or EPSS.

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id]
├── has_exploit                  ❌  always emitted as false (KEV implies active exploitation, but this flag is not set here)
│
├── cve{}
│   ├── cve_id                   ✅  seed only (not overwritten if already set)
│   ├── status                   ❌  NVD only
│   ├── published                ❌  NVD only
│   ├── updated                  ❌  NVD only
│   ├── epss{}                   ❌  EPSS vendor
│   ├── kev{}
│   │   ├── date_added           ✅  dateAdded
│   │   ├── due_date             ✅  dueDate
│   │   ├── known_ransomware     ✅  knownRansomwareCampaignUse (coerced — see Notes)
│   │   └── required_action      ✅  requiredAction
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ❌
├── descriptions[]               ❌  (shortDescription indexed but not written)
├── cvss[]                       ❌
├── cwes[]                       ❌  (cwes indexed but not written)
├── references[]                 ❌
├── advisories[]                 ❌
├── upstream[]                   ❌
├── packages[]                   ❌
├── mitigations[]                ❌
├── impacts[]                    ❌
├── exploits[]                   ❌
└── history[]                    ❌  no history events emitted
```
