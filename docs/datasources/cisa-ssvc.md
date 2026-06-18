# CISA SSVC (Stakeholder-Specific Vulnerability Categorization)

Enrichment-only source. It populates a single sub-object — `cve.ssvc{}` — and
contributes nothing else to the LVE record.

## cisagov/vulnrichment
- **URL:** `https://github.com/cisagov/vulnrichment` (branch `develop`)
- **Official:** Yes — CISA-maintained
- **Format:** CVE Record JSON 5.x; SSVC decision points live in the CISA-ADP container under `containers.adp[].metrics[].other` (`type == "ssvc"`)
- **Local path:** `repo/` (shallow git checkout) → reduced to `ssvc_index.json` (`{cve_id: {ssvc_*}}`)
- **Sync:** shallow clone (`--depth=1 --branch=develop`) on first run, `git pull --ff-only` afterwards; every `CVE-*.json` is scanned for an ADP container whose `providerMetadata.shortName == "CISA-ADP"`, and the SSVC decision options are extracted
- **Content:** CISA's structured triage decision points per CVE (only CVEs CISA has actively enriched)

## Field mapping

The sync step pulls the three SSVC decision options plus a timestamp into
`ssvc_index.json`. The transform normalises the three decision values to
lowercase and writes them; `ssvc_timestamp` is collected by sync but **not**
written by the transform. A record is **skipped entirely** when `exploitation`
cannot be normalised to one of `none` / `poc` / `active`.

```
CVE-*.json (CISA-ADP container)
└── containers.adp[] (shortName == "CISA-ADP")
    └── metrics[].other (type == "ssvc")
        └── content/
            ├── options[].Exploitation        ✅ → cve.ssvc.exploitation      (none|poc|active; required — else record skipped)
            ├── options[].Automatable         ✅ → cve.ssvc.automatable       (yes|no; null if unmappable)
            ├── options[]."Technical Impact"  ✅ → cve.ssvc.technical_impact  (partial|total; null if unmappable)
            └── timestamp                      ✗  (indexed as ssvc_timestamp by sync, not written)

cveMetadata.cveId                              ✅ → aliases[0] + cve.cve_id

Legend: ✅ imported  ✗ not imported
```

### Value normalisation

CISA stores values in title-case; the transform lowercases and maps them:

| Source value | LVE value |
|---|---|
| `None` | `none` |
| `PoC` | `poc` |
| `Active` | `active` |
| `Yes` | `yes` |
| `No` | `no` |
| `Partial` | `partial` |
| `Total` | `total` |

Any value not present in these maps becomes `null` (and, for `exploitation`,
causes the whole record to be skipped).

## Notes
- Pure enrichment: no titles, descriptions, CVSS, CWEs, references, advisories, or packages are written.
- `cve.cve_id` is written as a seed only — not authoritative and not overwritten if already set.
- The decision timestamp is discarded by the transform, so no `ssvc_updated` history event is produced.
- `exploitation=active` is a strong, often earlier/broader signal than KEV; `automatable=yes` + `exploitation=active` is the highest-priority SSVC combination.

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id]
├── has_exploit                  ❌  always emitted as false
│
├── cve{}
│   ├── cve_id                   ✅  seed only (not overwritten if already set)
│   ├── status                   ❌  NVD only
│   ├── published                ❌  NVD only
│   ├── updated                  ❌  NVD only
│   ├── epss{}                   ❌  EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}
│       ├── exploitation         ✅  options[].Exploitation (required)
│       ├── automatable          ✅  options[].Automatable
│       └── technical_impact     ✅  options[]."Technical Impact"
│
├── titles[]                     ❌
├── descriptions[]               ❌
├── cvss[]                       ❌
├── cwes[]                       ❌
├── references[]                 ❌
├── advisories[]                 ❌
├── upstream[]                   ❌
├── packages[]                   ❌
├── mitigations[]                ❌
├── impacts[]                    ❌
├── exploits[]                   ❌
└── history[]                    ❌  no history events emitted (timestamp discarded)
```
