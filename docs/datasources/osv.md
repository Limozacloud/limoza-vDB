# OSV (osv.dev)

OSV is Google's distributed vulnerability database. This importer ingests the
**package-ecosystem** advisories (PyPI, npm, Go, crates.io, RubyGems, NuGet, Maven,
Packagist, Hex, Pub) and writes affected packages and fix versions to `upstream[]`,
keyed by ecosystem PURL. It is structurally the same OSV format that GHSA uses, with
osv.dev as the advisory source.

OSV-prefixed records (e.g. `PYSEC-`, `GO-`, `RUSTSEC-`) are imported here; primary IDs
starting with `CVE-` or `GHSA-` are skipped (handled by the NVD and GHSA importers
respectively).

## OSV GCS package-ecosystem advisories
- **URL:** `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`
- **Official:** Yes — Google/OSV-maintained
- **Format:** OSV (JSON), one advisory per file, distributed as per-ecosystem `all.zip`
- **Local path:** `osv/<Ecosystem>/<advisory>.json` (ecosystem name spaces → underscores, e.g. `crates.io/`)
- **Sync:** downloads `all.zip` for every ecosystem (16 parallel workers), extracts, then builds `osv/osv_index.json` ({CVE-ID → [relative paths]}) from `related` + `aliases` + `upstream` references, and writes `osv/checkpoint.json` with the sync timestamp.
- **Content:** ecosystem package advisories with affected version ranges, fix versions, CVSS, CWE, and references.

> **Note on ecosystems.** Sync also downloads the **OS** ecosystems (AlmaLinux,
> Rocky Linux, Red Hat, Debian, Ubuntu, Alpine), but those are used only for the
> OSV cross-check (`compare.py` / `verify` command) — they are **not** ingested here.
> Only the package ecosystems (`PKG_ECOSYSTEMS`) are imported into the DB.

```
osv/
├── id                                  ✅ → aliases[] (OSV-ID) + advisories[].@id   (CVE-/GHSA- prefixes ⇒ skipped)
├── withdrawn                           ✅ → record skipped entirely if present
├── aliases[] + related[]/
│   └── [CVE-*]                         ✅ → cve.cve_id (first) + aliases[]  (no CVE found ⇒ skipped)
├── summary                             ✅ → titles[].value + descriptions[].value (fallback)
├── details                             ✅ → descriptions[].value (preferred over summary)
├── published                           ✅ → advisories[].published + history[].date (advisory_added)
├── modified                            ✅ → advisories[].updated + history[].date (advisory_updated, if ≠ published)
├── severity[]/                         (CVSS vectors)
│   ├── type (CVSS_V4/V3/V2)            ✅ → cvss[].version (4.0/3.1/2.0)
│   └── score (vector string)           ✅ → cvss[].vector
├── database_specific/
│   ├── cvss                            ✅ → cvss[].score   (numeric; entry skipped if absent/non-numeric)
│   ├── severity                        ✅ → cvss[].severity (mapped)
│   └── cwe_ids[]                       ✅ → cwes[].id  (CWE-* only)
├── references[]/
│   ├── url                             ✅ → references[].url
│   └── type                            ✅ → references[].type  (mapped, else "web")
└── affected[]/
    ├── package/
    │   ├── purl                        ✅ → upstream[].purl  (used verbatim as hint if present)
    │   ├── ecosystem                   ✅ → upstream[].purl (ecosystem mapping, when no purl hint)
    │   └── name                        ✅ → upstream[].purl
    ├── ranges[]/
    │   ├── [type=ECOSYSTEM|SEMVER]
    │   │   └── events[introduced|fixed|last_affected]  ✅ → upstream[].ranges[] + upstream[].fix_version
    │   └── [type=GIT].events[fixed]    ✅ → upstream[].fix_commit
    ├── versions[]                      ✅ → upstream[].versions
    └── database_specific/              ✗
```

Legend: ✅ imported  ✗ not imported

## PURL

OSV emits **ecosystem PURLs** on `upstream[]`. If the source supplies
`affected[].package.purl`, it is used **verbatim**; otherwise the PURL is derived from
`ecosystem` + `name`. An unmapped ecosystem (with no purl hint) yields no PURL and the
affected entry is dropped.

| OSV ecosystem | PURL produced |
|---|---|
| `npm` | `pkg:npm/<name>` (scoped `@scope/pkg` → `pkg:npm/%40scope/pkg`) |
| `PyPI` | `pkg:pypi/<name>` (lowercased, `-` → `_`) |
| `Go` | `pkg:golang/<module>` |
| `Maven` | `pkg:maven/<group>/<artifact>` (splits on `:` or `/`) |
| `RubyGems` / `Ruby` | `pkg:gem/<name>` |
| `NuGet` | `pkg:nuget/<name>` |
| `crates.io` / `Cargo` | `pkg:cargo/<name>` |
| `Packagist` / `Composer` | `pkg:composer/<name>` |
| `Hex` | `pkg:hex/<name>` |
| `Pub` | `pkg:pub/<name>` |
| `GitHub Actions` | `pkg:githubactions/<name>` |
| `Swift` | `pkg:swift/<name>` |
| (any other) | none — entry skipped |

The PURL is a package identity (no version). Versions live in `upstream[].ranges[]`
(introduced/fixed/last_affected), `upstream[].fix_version` (latest fixed),
`upstream[].fix_commit` (from GIT ranges), and `upstream[].versions[]`.

## State mapping

OSV writes to `upstream[]`, not `packages[]`, and does not emit
`affected_state` / `remediation_state`. Affected status is implicit in the ranges:
`introduced: "0"` with a `fixed` bound means all versions below the fix are affected;
a `last_affected` event marks the last affected version where no fix is recorded.

CVSS severity is mapped `CRITICAL→critical`, `HIGH→high`, `MEDIUM→medium`,
`LOW→low`, `NONE→informational`. Reference types map
`ADVISORY→advisory`; `FIX`/`GIT→patch`; `REPORT→report`; `ARTICLE→article`;
`WEB`/`PACKAGE`/`EVIDENCE`/`DETECTION→web`; unmapped → `web`.

## Notes
- A record is **skipped** (returns `None`) if: the primary `id` is missing or starts with `CVE-`/`GHSA-`; it is `withdrawn`; no `CVE-*` is found in `aliases` **or** `related`; or it produces **no** `upstream[]` entries (every affected package had an unmappable ecosystem).
- CVE detection considers both `aliases[]` and `related[]` (GHSA considers only `aliases[]`).
- The Swift/GitHub Actions mappings exist in code; the Erlang→hex fallback present in GHSA is **not** in the OSV mapper.
- Duplicate `affected[]` entries for the same `(ecosystem, name)` are merged: ranges concatenated, `fix_version` / `versions` updated.
- `cve.cve_id` is the only `cve{}` field OSV writes — it never sets the spine (status/published/updated); that comes from NVD.
- CVSS is only inserted when `database_specific.cvss` is a parseable numeric score.
- The transform includes empty `mitigations[]` and `impacts[]` keys in its return dict but never populates them.
- The transform returns a single dict (or `None`), unlike GHSA/NVD which return a list.

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [OSV-ID] + CVE-* from aliases[]/related[]
├── has_exploit                  ❌  not written — no exploit data
│
├── cve{}
│   ├── cve_id                   ✅  first CVE-* found  (seed only — spine not set)
│   ├── status                   ❌  NVD only
│   ├── published               ❌  NVD only
│   ├── updated                 ❌  NVD only
│   ├── epss{}                   ❌  EPSS vendor
│   ├── kev{}                    ❌  CISA-KEV vendor
│   └── ssvc{}                   ❌  CISA-SSVC vendor
│
├── titles[]                     ✅  summary
├── descriptions[]              ✅  details (or summary fallback)
├── cvss[]                       ✅  severity[].score (vector) + database_specific.cvss/severity
├── cwes[]                       ✅  database_specific.cwe_ids (CWE-* only); name = null
├── references[]                 ✅  references[].url + mapped type
│
├── advisories[]
│   ├── @id                      ✅  OSV-ID
│   ├── url                      ✅  https://osv.dev/vulnerability/<OSV-ID>
│   ├── published               ✅  published
│   ├── updated                 ✅  modified
│   └── vendor_data             ❌  not written
│
├── upstream[]
│   ├── @id                      ✅  <OSV-ID>:<ecosystem>:<name>
│   ├── purl                     ✅  package.purl hint, else ecosystem PURL
│   ├── fix_version             ✅  latest fixed version from ECOSYSTEM/SEMVER ranges
│   ├── fix_commit              ✅  first fixed commit from GIT ranges
│   ├── ranges[]                ✅  {introduced, fixed, last_affected}
│   ├── versions[]              ✅  affected[].versions
│   ├── source                  ✅  "osv"
│   └── advisory_ref            ✅  OSV-ID
│
├── packages[]                   ❌  not written — OSV tracks upstream ecosystems only
│
├── mitigations[]                ❌  key present but never populated
├── impacts[]                    ❌  key present but never populated
├── exploits[]                   ❌  not written
│
└── history[]
    ├── date                     ✅  published (advisory_added) / modified (advisory_updated)
    ├── event                    ✅  advisory_added / advisory_updated
    ├── source                   ✅  "osv"
    └── detail                   ✅  OSV-ID
```
