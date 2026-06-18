# GHSA (GitHub Security Advisories)

GHSA is the primary source for **language-ecosystem** fixes (npm, PyPI, Go, Maven,
crates.io, NuGet, RubyGems, and more). It is distributed in OSV format. Affected
packages and fix versions are written to `upstream[]` (not `packages[]`), keyed by
ecosystem PURL.

## github/advisory-database
- **URL:** `https://github.com/github/advisory-database`
- **Official:** Yes — GitHub-maintained
- **Format:** OSV (JSON), one advisory per file
- **Local path:** `advisories/github-reviewed/<year>/<id>/GHSA-*.json` and `advisories/unreviewed/<year>/<id>/GHSA-*.json`
- **License:** CC BY 4.0
- **Sync:** shallow `git clone --depth=1` on first run, `git pull --ff-only` afterwards. Both `github-reviewed` and `unreviewed` subtrees are ingested.
- **Content:** advisories for ecosystem packages with affected version ranges, upstream fix versions, CVSS, CWE, and references. Each record requires a CVE alias to be ingested.

```
osv/
├── id                                  ✅ → aliases[] (GHSA-ID) + advisories[].@id
├── withdrawn                           ✅ → record skipped entirely if present
├── aliases[]/
│   └── [CVE-*]                         ✅ → cve.cve_id (first) + aliases[]  (no CVE alias ⇒ skipped)
├── summary                             ✅ → titles[].value + descriptions[].value (fallback)
├── details                             ✅ → descriptions[].value (preferred over summary)
├── published                           ✅ → advisories[].published
├── modified                            ✅ → advisories[].updated
├── severity[]/                         (CVSS vectors)
│   ├── type (CVSS_V4/V3/V2)            ✅ → cvss[].version (4.0/3.1/2.0)
│   └── score (vector string)           ✅ → cvss[].vector
├── database_specific/
│   ├── cvss                            ✅ → cvss[].score   (numeric; entry skipped if absent/non-numeric)
│   ├── severity                        ✅ → cvss[].severity (mapped)
│   ├── cwe_ids[]                       ✅ → cwes[].id  (CWE-* only)
│   └── github_reviewed                 ✅ → advisories[].vendor_data.github_reviewed
├── references[]/
│   ├── url                             ✅ → references[].url
│   └── type                            ✅ → references[].type  (mapped, else "web")
└── affected[]/
    ├── package/
    │   ├── ecosystem                   ✅ → upstream[].purl (ecosystem mapping)
    │   └── name                        ✅ → upstream[].purl
    ├── ranges[]/
    │   ├── [type=ECOSYSTEM|SEMVER]
    │   │   └── events[introduced|fixed|last_affected]  ✅ → upstream[].ranges[] + upstream[].fix_version
    │   └── [type=GIT].events[fixed]    ✅ → upstream[].fix_commit
    ├── versions[]                      ✅ → upstream[].versions
    └── database_specific/              ✗  (e.g. last_known_affected_version_range not used)
```

Legend: ✅ imported  ✗ not imported

## PURL

GHSA emits **ecosystem PURLs** on `upstream[]`, derived from
`affected[].package.ecosystem` + `name`. An unmapped ecosystem yields no PURL and the
affected entry is dropped.

| GHSA ecosystem | PURL produced |
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
| `Erlang` | `pkg:hex/<name>` |
| (any other) | none — entry skipped |

The PURL is a package identity (no version). Affected/fixed versions live in
`upstream[].ranges[]` (introduced/fixed/last_affected), `upstream[].fix_version`
(latest fixed), `upstream[].fix_commit` (from GIT ranges), and the explicit
`upstream[].versions[]` list.

## State mapping

GHSA writes to `upstream[]`, not `packages[]`, and does not emit
`affected_state` / `remediation_state`. Affected status is implicit in the version
ranges: `introduced: "0"` with a `fixed` bound means every version below the fix is
affected; a `last_affected` event marks the last affected version where no fix exists.

CVSS severity is mapped `CRITICAL→critical`, `HIGH→high`, `MEDIUM→medium`,
`LOW→low`, `NONE→informational`. Reference types map
`ADVISORY→advisory`; `FIX`/`GIT→patch`; `REPORT→report`; `ARTICLE→article`;
`WEB`/`PACKAGE`/`EVIDENCE`/`DETECTION→web`; unmapped → `web`.

## Notes
- A record is **skipped** if it is `withdrawn`, has no `id`, or carries no `CVE-*` alias. GHSA-only advisories without a CVE are not ingested.
- `github_reviewed` distinguishes human-curated advisories from auto-imported NVD entries; it is preserved in `advisories[].vendor_data.github_reviewed`. Unreviewed advisories often lack package-level data.
- Duplicate `affected[]` entries for the same `(ecosystem, name)` are merged: ranges are concatenated and `fix_version` / `versions` updated.
- `cve.cve_id` is the only `cve{}` field GHSA writes — it never sets the `cve{}` spine (status/published/updated); that comes from NVD.
- CVSS is only inserted when `database_specific.cvss` is a parseable numeric score, even if a vector string is present.
- The transform never writes `packages[]`, `mitigations[]`, `impacts[]`, `exploits[]`, or `history[]`.

---

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [GHSA-ID] + CVE-* aliases
├── has_exploit                  ❌  not written — no exploit data
│
├── cve{}
│   ├── cve_id                   ✅  first CVE-* alias  (seed only — spine not set)
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
│   ├── @id                      ✅  GHSA-ID
│   ├── url                      ✅  https://github.com/advisories/<GHSA-ID>
│   ├── published               ✅  published
│   ├── updated                 ✅  modified
│   └── vendor_data             ✅  {"github_reviewed": bool}
│
├── upstream[]
│   ├── @id                      ✅  <GHSA-ID>:<ecosystem>:<name>
│   ├── purl                     ✅  ecosystem PURL (see PURL section)
│   ├── fix_version             ✅  latest fixed version from ECOSYSTEM/SEMVER ranges
│   ├── fix_commit              ✅  first fixed commit from GIT ranges
│   ├── ranges[]                ✅  {introduced, fixed, last_affected}
│   ├── versions[]              ✅  affected[].versions
│   ├── source                  ✅  "ghsa"
│   └── advisory_ref            ✅  GHSA-ID
│
├── packages[]                   ❌  not written — GHSA tracks upstream ecosystems only
│
├── mitigations[]                ❌  not written
├── impacts[]                    ❌  not written
├── exploits[]                   ❌  not written
│
└── history[]                    ❌  not written
```
