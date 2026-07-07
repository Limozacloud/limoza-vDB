# CVE List

The CVE List is the baseline source: the authoritative record for every CVE, as
published by the assigning CNA through the CVE Program. It is the only writer of
`cve_record` and the primary author of a CVE's description, CVSS, CWE, and
references.

## Feed
- **URL:** `https://github.com/CVEProject/cvelistV5`
- **Official:** Yes — the CVE Program's canonical repository
- **Format:** CVE Record Format 5.x (JSON), one file per CVE
- **Local path:** `repo/cves/<year>/<N>xxx/CVE-<year>-<id>.json`
- **Sync:** shallow git clone, then pull; a gate skips the run when `HEAD` is unchanged
- **Content:** lifecycle state, assigner, dates, title, descriptions, CVSS, CWE,
  references, and the ADP (e.g. CISA-ADP) enrichment containers

## Incremental ingest

The ingest tracks its own last-ingested commit. On a repeat run it reparses only the
CVE files that changed since then (`git diff`); on the first run, all of them. A
changed CVE's `cvelistv5`-origin rows are deleted and reinserted, so a record that
loses data never leaves stale rows behind.

## Provenance

Every enrichment row is written with `origin = cvelistv5`. The `source` records who
authored it inside the record:

- **`cna`** — the CNA container (the assigner's own data).
- an **ADP short name** — an Authorized Data Publisher container (CISA-ADP, …),
  collected into the [`adp`](../ingest/schema.md#dictionaries) dictionary by UUID.

The assigner becomes `cve_record.assigner` → the [`cna`](cna.md) directory, which is
the **L1** [advisory tier](../advisory-tiers.md). References written here are also
what the **L2** upstream-advisory patterns match against.

## Field mapping

```
cveMetadata
├── cveId                               ✅ → cve_record.cve_id + cve spine
├── state                               ✅ → cve_record.state
├── assignerShortName                   ✅ → cve_record.assigner → cna
├── dateReserved/Published/Updated      ✅ → cve_record.date_*
containers.cna / containers.adp[]
├── title                               ✅ → cve_record.title
├── descriptions[]                      ✅ → cve_desc
├── metrics[].cvssV*                    ✅ → cve_cvss
├── problemTypes[].descriptions[].cweId ✅ → cve_cwe
├── references[]                        ✅ → cve_ref
├── solutions[] / workarounds[]         ✅ → cve_solution / cve_workaround
├── impacts[].capecId                   ✅ → cve_impact
├── affected[].cpes + versions[]        ✅ → affected (coord=cpe) — CNA version ranges
└── providerMetadata.orgId              ✅ → cna.uuids / adp.uuid (provenance join)
```

---

## Affected versions (L4)

The `cvelistv5` [affected extractor](../affected-versions.md) synthesises the **CPE lane**
(`coord=cpe`) from a CNA's `affected[]` entries — `versions[]` (`lessThan` → `fixed`,
`lessThanOrEqual` → `last_affected`, bare → exact) against the entry's CPE, validated via
`cpe_norm`. This is the fallback for CVEs NVD has no configuration for.

It also resolves **name-only** CNA entries — those that identify the product by
`vendor`/`product` with no `cpes` field — through a small curated `(vendor, product) → CPE`
map (currently `("python software foundation", "cpython") → cpe:2.3:a:python:python`). This
matters where a CNA carries richer **per-branch** ranges than NVD keeps: the PSF/CPython
records give the real backport fix per release line (`< 3.13.14`, `< 3.14.5`) where NVD
collapses everything to a single mainline `fixed 3.15.0`. The matcher's reach-any-fix logic
then lets a patched 3.13.14 host clear NVD's row. Microsoft vendor CPEs are excluded here
(MSRC is authoritative).

---

## Schema coverage

```
cve                ✅  the spine (every CVE id)
cve_record         ✅  state, assigner, dates, title, exploit_note
cve_desc           ✅  source = cna | <adp>
cve_cvss           ✅
cve_cwe            ✅
cve_ref            ✅
cve_solution       ✅  where the record provides one
cve_workaround     ✅  where the record provides one
cve_impact         ✅  CAPEC, where provided
cve_alias          ✅  where the record provides one
affected           ✅  CPE lane (coord=cpe) — CNA version ranges + name-only CNA via curated map
adp                ✅  ADP publishers seen (byproduct)
advisory / cve_vendor   ❌  distros/vendors
exploits / epss / kev / ssvc   ❌  their own sources
```
