# CWE Dictionary

The CWE (Common Weakness Enumeration) dictionary is a **reference source**, not a
per-CVE source. It does **not** produce LVE records of its own. It serves one purpose:

- **Weakness definitions** — populates the shared `cwe` dictionary table with the full
  definition of every weakness (mitigations, consequences, likelihood, …) so
  downstream consumers (including an LLM authoring mitigation guidance) have the complete
  context from the database alone.

## CWE-CAPEC REST-API-wg (json_repo/W)
- **URL:** `https://github.com/CWE-CAPEC/REST-API-wg`
- **Official:** Yes — MITRE CWE/CAPEC working-group repository
- **Format:** one JSON file per weakness under `json_repo/W/` (`*.json`)
- **Local path:** `cwe-db/json_repo/W/*.json`
- **Sync:** sparse `git` clone (`--depth=1 --filter=blob:none --sparse`) restricted to the
  `json_repo/W` directory; on subsequent runs the sparse-checkout set is re-applied and
  the repo is updated with `git pull --ff-only`. After sync it prints the number of
  weakness definitions found.
- **Content:** each file holds a full weakness definition. The fields consumed by the
  pipeline are listed below.

## Fields consumed

`ingest.cwe._load()` reads every `json_repo/W/*.json` file once and builds an in-memory map
(cached for the process) of `CWE-<ID>` → definition:

| json_repo/W field | Mapped to (`cwe` table column) |
|-------------------|--------------------------------|
| `ID` | `cwe_id` (as `CWE-<ID>`) |
| `Name` | `name` |
| `Abstraction` | `abstraction` |
| `Description` | `description` |
| `ExtendedDescription` | `extended_description` |
| `LikelihoodOfExploit` | `likelihood_of_exploit` |
| `CommonConsequences[]` | `common_consequences` (jsonb: `{scope, impact, note}`) |
| `PotentialMitigations[]` | `potential_mitigations` (jsonb: `{phase, strategy, description, effectiveness}`) |
| `ModesOfIntroduction[]` | `modes_of_introduction` (jsonb: `{phase, note}`) |
| `DetectionMethods[]` | `detection_methods` (jsonb: `{method, description, effectiveness}`) |
| `RelatedAttackPatterns[]` | `related_attack_patterns` (jsonb: `["CAPEC-<n>", …]`) |
| `RelatedWeaknesses[]` | `related_weaknesses` (jsonb: `{nature, cwe_id, view_id}`) |

All other fields (DemonstrativeExamples, ObservedExamples, TaxonomyMappings, References,
ContentHistory, …) are not read. Files that fail to parse are silently skipped. If
`json_repo/W` does not exist, the lookup is an empty map.

## Import

Run `import cwe` **before** other vendor imports. It bulk-inserts all ~940 weakness
definitions into the `cwe` table in a single pass. Subsequent vendor imports
(`nvd-github`, `redhat`, etc.) write only `cwe_id` references to `lve_cwes` — no
CWE detail lookup or insertion happens during those imports.

## Notes
- `lve_cwes.cwe_id` references `cwe.cwe_id` loosely; there is **no** foreign key, because
  sources occasionally cite ids outside the synced Weakness set (categories, `CWE-NVD-*`).
  In Hasura the relationship `lve_cwes → cwe` is configured as a manual relationship.
- Only `json_repo/W/` (Weaknesses) is synced — Categories, Views, and CAPEC data in the
  upstream repo are not fetched.
- The in-memory map is cached on first use for the lifetime of the ingest process.

## Schema Coverage

Owns the `cwe` dictionary table (one row per weakness, ~940 total). Vendor imports
reference CWE ids via `lve_cwes.cwe_id`; the full definition is obtained by joining
`lve_cwes → cwe` on `cwe_id`.
