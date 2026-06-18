# EPSS (FIRST.org)

Enrichment-only source. It populates a single sub-object — `cve.epss{}` — and
contributes nothing else to the LVE record.

## EPSS API
- **URL:** `https://api.first.org/data/v1/epss`
- **Official:** Yes — FIRST.org-maintained
- **Format:** JSON, paginated (10,000 rows per page via `?limit=10000&offset=N`)
- **Local path:** `epss.json` (a flat `{cve_id: [score, percentile, date]}` index built by sync)
- **Sync:** full pull on every run — the API is paged from `offset=0` until `offset >= total`, with a 1 s pause between pages; the resulting index is written to `epss.json`
- **Content:** Exploit Prediction Scoring System — per-CVE probability of exploitation in the wild within the next 30 days, plus the relative percentile rank

## Field mapping

The sync step reduces each API row to a three-element list `[score, percentile, date]`.
The transform step skips any list with fewer than two elements (`date` is optional).

```
api.first.org/data/v1/epss
└── data[]/
    ├── cve                       ✅ → aliases[0] + cve.cve_id
    ├── epss        (→ list[0])   ✅ → cve.epss.score        (float)
    ├── percentile  (→ list[1])   ✅ → cve.epss.percentile   (float)
    ├── date        (→ list[2])   ✅ → cve.epss.date         (optional; null if absent)
    ├── model_version             ✗
    └── (other API metadata)      ✗

Legend: ✅ imported  ✗ not imported
```

## Notes
- Pure enrichment: no titles, descriptions, CVSS, CWEs, references, advisories, or packages are written.
- During sync, missing `epss`/`percentile` values are coerced to `0.0`; `date` may be `null`.
- The transform skips a CVE only when the stored list has fewer than two elements (i.e. score and percentile are both required; date is optional).
- `cve.cve_id` is written as a seed only — it is not authoritative and does not overwrite an existing CVE record.
- High EPSS combined with CISA KEV presence is the strongest exploitation-risk signal in the database.

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id]
├── has_exploit                  ❌  always emitted as false (no exploit data)
│
├── cve{}
│   ├── cve_id                   ✅  seed only (not overwritten if already set)
│   ├── status                   ❌  NVD only
│   ├── published                ❌  NVD only
│   ├── updated                  ❌  NVD only
│   ├── epss{}
│   │   ├── score                ✅  data[].epss
│   │   ├── percentile           ✅  data[].percentile
│   │   └── date                 ✅  data[].date (optional)
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
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
└── history[]                    ❌  no history events emitted
```
