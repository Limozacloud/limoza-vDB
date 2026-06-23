# CISA SSVC (Stakeholder-Specific Vulnerability Categorization)

Enrichment-only source. Populates the `ssvc` table — one row per CVE — and
contributes nothing else to the database.

## cisagov/vulnrichment

- **URL:** `https://github.com/cisagov/vulnrichment` (branch `develop`)
- **Official:** Yes — CISA-maintained
- **Format:** CVE Record JSON 5.x; SSVC decision points live in the CISA-ADP container
  under `containers.adp[].metrics[].other` (`type == "ssvc"`)
- **Local path:** `ssvc/repo/` (shallow git checkout) → compact index at `ssvc/ssvc_index.json`
  (`{cve_id: {exploitation, automatable, technical_impact}}`)
- **Sync:** shallow clone (`--depth=1 --branch=develop`) on first run, `git pull --ff-only`
  afterwards; the index rebuild is gated on the post-pull HEAD commit hash — if HEAD
  is unchanged and `ssvc_index.json` exists, the expensive 156 k-file scan is skipped
- **Content:** CISA's structured triage decision points per CVE (only CVEs CISA has
  actively enriched)

## Field mapping

The sync step scans every `CVE-*.json` in the repo, finds the CISA-ADP container
(`providerMetadata.shortName == "CISA-ADP"`), and extracts the three SSVC option
values into `ssvc_index.json`. The ingest step normalises the values to lowercase and
writes them; rows where `exploitation` cannot be normalised are skipped entirely.

```
CVE-*.json (CISA-ADP container)
└── containers.adp[] (shortName == "CISA-ADP")
    └── metrics[].other (type == "ssvc")
        └── content/
            ├── options[].Exploitation        ✅ → ssvc.exploitation      (none|poc|active; required — else row skipped)
            ├── options[].Automatable         ✅ → ssvc.automatable       (yes|no; NULL if unmappable)
            ├── options[]."Technical Impact"  ✅ → ssvc.technical_impact  (partial|total; NULL if unmappable)
            └── timestamp                      ✗  (not written)

cveMetadata.cveId                             ✅ → ssvc.cve_id  +  cve spine (ON CONFLICT DO NOTHING)

Legend: ✅ imported  ✗ not imported
```

### Value normalisation

CISA stores values in title-case; the ingest step lowercases and maps them:

| Source value | DB value |
|---|---|
| `None` | `none` |
| `PoC` | `poc` |
| `Active` | `active` |
| `Yes` | `yes` |
| `No` | `no` |
| `Partial` | `partial` |
| `Total` | `total` |

Any value absent from these maps becomes `NULL` (and for `exploitation`, causes the
whole row to be skipped).

## Notes

- Pure enrichment: no descriptions, CVSS, CWEs, references, or advisory data are
  written.
- The SSVC `timestamp` field is collected by sync but not written to the database.
- The ingest pattern is **DELETE + INSERT** in a single transaction. `DELETE` (not
  `TRUNCATE`) takes only `ROW EXCLUSIVE`, so concurrent dashboard reads continue via
  MVCC until commit.
- `exploitation=active` is a strong, often earlier/broader signal than KEV;
  `automatable=yes` combined with `exploitation=active` is the highest-priority SSVC
  combination.

---

## Schema coverage

```
cve                ✅  ON CONFLICT DO NOTHING — seeds the spine for every SSVC-enriched CVE
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
epss               ❌  FIRST EPSS source
kev                ❌  CISA KEV source
ssvc               ✅  cve_id, exploitation, automatable, technical_impact
```
