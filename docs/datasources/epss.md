# EPSS (FIRST.org)

Enrichment-only source. Populates the `epss` table — one row per CVE — and
contributes nothing else to the database.

## EPSS API

- **URL:** `https://api.first.org/data/v1/epss`
- **Official:** Yes — FIRST.org-maintained
- **Format:** JSON, paginated (10,000 rows per page via `?limit=10000&offset=N`)
- **Local path:** `epss/epss.json` (a flat `{cve_id: [score, percentile, date]}` index built by sync)
- **Sync:** full pull on every run — the API is paged from `offset=0` until `offset >= total`, with a 1 s pause between pages; the resulting index is written to `epss.json`
- **Content:** Exploit Prediction Scoring System — per-CVE probability of exploitation in the wild within the next 30 days, plus the relative percentile rank

## Field mapping

The sync step reduces each API row to a three-element list `[score, percentile, date]`.
The ingest step skips any entry with fewer than two elements (`date` is optional).

```
api.first.org/data/v1/epss
└── data[]/
    ├── cve                       ✅ → epss.cve_id  +  cve spine (ON CONFLICT DO NOTHING)
    ├── epss        (→ list[0])   ✅ → epss.score        (float; 0.0 if missing)
    ├── percentile  (→ list[1])   ✅ → epss.percentile   (float; 0.0 if missing)
    ├── date        (→ list[2])   ✅ → epss.date         (optional; NULL if absent)
    ├── model_version             ✗
    └── (other API metadata)      ✗

Legend: ✅ imported  ✗ not imported
```

## Notes

- Pure enrichment: no descriptions, CVSS, CWEs, references, advisories, or exploit
  data are written.
- Missing `epss` / `percentile` values are coerced to `0.0` during sync; `date` is
  stored as `NULL` when absent.
- The ingest pattern is a pure **UPSERT** (`ON CONFLICT (cve_id) DO UPDATE`). EPSS
  publishes a full daily snapshot and never removes CVEs, so no sweep or delete is
  needed — scores are simply overwritten each run.
- High EPSS combined with CISA KEV presence is the strongest exploitation-risk signal
  in the database.

---

## Schema coverage

```
cve                ✅  ON CONFLICT DO NOTHING — seeds the spine for every scored CVE
cve_record         ❌  CVE List only
cve_cvss           ❌
cve_cwe            ❌
cve_desc           ❌
cve_ref            ❌
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ❌
advisory_cve       ❌
cve_vendor         ❌
exploits           ❌
epss               ✅  cve_id, score, percentile, date
kev                ❌  CISA KEV source
ssvc               ❌  CISA SSVC source
```
