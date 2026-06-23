# OSV — native ecosystem advisory DBs

This importer ingests the **native** advisory databases of five language ecosystems
that publish their own advisories independently of GHSA:

| Ecosystem | OSV id prefix | Source name | Advisory DB |
|---|---|---|---|
| Python (PyPI) | `PYSEC-` | `pypa` | Python Packaging Advisory Database |
| Go | `GO-` | `go` | Go Vulnerability Database |
| Rust (crates.io) | `RUSTSEC-` | `rustsec` | RustSec Advisory DB |
| Erlang (Hex) | `EEF-` | `eef` | Erlang Ecosystem Foundation |
| PHP (Packagist) | `DRUPAL-` | `drupal` | Drupal Security Advisories |

These are **L3 downstream** sources in the [advisory tier](../advisory-tiers.md) model
— they are ecosystem package maintainers who ship fixes and publish their own bulletins.
GHSA is the L2 upstream layer that aggregates many of the same records under GHSA ids;
it has its own importer ([ghsa.md](ghsa.md)) and is not ingested here.

Records with a primary id starting with `GHSA-`, `CVE-`, `MAL-`, or plain `OSV-` are
dropped. Only the five native prefixes listed above are kept.

## OSV GCS per-ecosystem zips

- **URL:** `https://osv-vulnerabilities.storage.googleapis.com/{Ecosystem}/all.zip`
  (one zip per ecosystem: `PyPI`, `Go`, `crates.io`, `Hex`, `Packagist`)
- **Official:** Yes — Google/OSV-maintained distribution
- **Format:** OSV (JSON), one advisory per file, packed into a per-ecosystem `all.zip`
- **Local path:** `{osv}/{Ecosystem}.zip`
- **Sync:** download `all.zip` for each of the five ecosystems. All files are replaced on every sync (no incremental).
- **Content:** ecosystem advisory ids, CVE aliases, description prose, published/modified dates, and affected package identities (PURLs). No CVSS or CWE fields are produced by this importer.

```
osv/
├── id                                  ✅ → advisory.advisory_id (e.g. "PYSEC-2024-42")
│                                           + advisory.url  (see URL derivation below)
│                                           (GHSA-/CVE-/MAL-/OSV- prefix → record skipped)
├── withdrawn                           ✅ → record skipped entirely if present
├── aliases[]
│   └── [CVE-*]                         ✅ → cve spine (cve.cve_id) + advisory_cve.cve_id
│                                           (no CVE alias → record skipped)
├── summary                             ✅ → advisory.title  (first 100 chars of details used as fallback)
├── details                             ✅ → cve_desc.value  (en; one row per (cve_id, source))
├── published                           ✅ → advisory.published
├── modified                            ✅ → advisory.modified
├── severity[]                          ✗  not consumed
├── database_specific/                  ✗  not consumed
├── references[]                        ✗  not consumed
└── affected[]/
    └── package/{purl, ecosystem, name} ✅ → purls collected for GHSA cross-alias disambiguation only
                                            (not written to any table; version ranges are phase 3)

Legend: ✅ imported  ✗ not imported
```

### Advisory URL derivation

The canonical URL per advisory id prefix:

| Prefix | URL pattern |
|---|---|
| `GO-` | `https://pkg.go.dev/vuln/{id}` |
| `RUSTSEC-` | `https://rustsec.org/advisories/{id}.html` |
| `PYSEC-` / `EEF-` / `DRUPAL-` | `affected[].database_specific.source` (first found), else `https://osv.dev/vulnerability/{id}` |

## Cross-alias disambiguation

Some native OSV records carry multiple CVE aliases because they describe a
vulnerability that was later split into separate CVEs, or because the upstream
advisory was filed before the CVEs were issued. Linking the advisory to every CVE
in its alias list would create spurious L3 advisory entries for CVEs the advisory
does not actually cover.

The importer uses GHSA's `cve_vendor.data.packages` (already in the database) as a
precise CVE→purl map. For a native advisory that lists more than one CVE alias, any
CVE whose GHSA-known package set does not intersect the advisory's own package set
is dropped from `advisory_cve`. The advisory row itself is still written; only the
loose cross-alias link is suppressed.

```
multi-CVE advisory?
  YES → for each cve_id:
          known = ghsa_purls[cve_id]    # from cve_vendor WHERE source='ghsa'
          if known AND advisory.purls AND (advisory.purls ∩ known) == ∅ → drop link
        else → write advisory_cve normally
```

This makes GHSA a dependency of the OSV ingest: the OSV importer reads the GHSA
purl map at startup. Run GHSA ingest before OSV ingest.

## Notes

- **`origin` and `source` are the same source name** (`pypa`, `go`, `rustsec`, `eef`,
  or `drupal`) — each native DB owns its own delete-scope slice.
- **`cve_desc`** is written with `origin = source` (e.g. `"pypa"`) and `source = NULL`
  (no CNA UUID — these are not CNAs). One row per `(cve_id, source)`.
- **No CVSS or CWE enrichment.** The OSV native-format files for these ecosystems
  rarely carry well-formed CVSS vectors; any available CVSS data comes from GHSA or
  the CVE List.
- **Affected package purls / version ranges** are collected internally for the
  cross-alias filter but are not written to any table. Full version range semantics
  belong to the phase-3 affected table.
- The importer produces one `advisory` row and one or more `advisory_cve` rows per
  record. No `cve_vendor` rows are written.
- `severity` in `advisory` is always `NULL` for these sources (the OSV files do not
  carry a uniform severity field that the importer consumes).

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ✅  details prose (en; one row per (cve_id, source))
cve_cvss           ❌  not written
cve_cwe            ❌  not written
cve_ref            ❌  not written
cve_solution       ❌  not written
cve_workaround     ❌  not written
cve_impact         ❌  not written
cve_alias          ❌  not written
advisory           ✅  native advisory id / url / title / published / modified
advisory_cve       ✅  advisory ↔ CVE links (cross-alias filtered via GHSA purl map)
cve_vendor         ❌  not written
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
