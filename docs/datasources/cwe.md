# CWE Dictionary

The CWE (Common Weakness Enumeration) dictionary is a **reference source**, not a
per-CVE source. It populates the standalone `cwe` table with the full definition of every
weakness — mitigations, consequences, likelihood of exploit, detection methods, and
related attack patterns — so that `cve_cwe.cwe_id` joins resolve to rich, structured
content. It writes no per-CVE rows; it is a reference dictionary.

## CWE-CAPEC REST-API-wg (`json_repo/W`)

- **URL:** `https://github.com/CWE-CAPEC/REST-API-wg`
- **Official:** Yes — MITRE CWE/CAPEC working-group repository
- **Format:** one JSON file per weakness under `json_repo/W/` (`CWE-<ID>.json`)
- **Local path:** `cwe-db/json_repo/W/*.json`
- **Sync:** sparse `git` clone (`--depth=1 --filter=blob:none --sparse`) restricted to
  the `json_repo/W` directory; subsequent runs apply `git pull --ff-only`. Only
  Weakness definitions are fetched — Categories, Views, and CAPEC data in the repo are
  not included in the sparse checkout.
- **Content:** each file holds a full weakness definition. Fields consumed are listed
  below; all others (DemonstrativeExamples, ObservedExamples, TaxonomyMappings,
  References, ContentHistory, …) are not read. Files that fail to parse are silently
  skipped.

```
json_repo/W/<CWE-ID>.json
├── ID                       ✅ → cwe.cwe_id                  (stored as "CWE-<ID>")
├── Name                     ✅ → cwe.name
├── Abstraction              ✅ → cwe.abstraction              (Base | Variant | Class | Pillar)
├── Description              ✅ → cwe.description
├── ExtendedDescription      ✅ → cwe.extended_description
├── LikelihoodOfExploit      ✅ → cwe.likelihood_of_exploit
├── CommonConsequences[]     ✅ → cwe.common_consequences      (jsonb: {scope, impact, note})
├── PotentialMitigations[]   ✅ → cwe.potential_mitigations    (jsonb: {phase, strategy,
│                                                                description, effectiveness})
├── ModesOfIntroduction[]    ✅ → cwe.modes_of_introduction    (jsonb: {phase, note})
├── DetectionMethods[]       ✅ → cwe.detection_methods        (jsonb: {method, description,
│                                                                effectiveness})
├── RelatedAttackPatterns[]  ✅ → cwe.related_attack_patterns  (jsonb: ["CAPEC-<n>", …])
├── RelatedWeaknesses[]      ✅ → cwe.related_weaknesses       (jsonb: {nature, cwe_id, view_id})
└── all other fields          ✗  not imported

Legend: ✅ imported  ✗ not imported
```

## Notes

- CWEs are deprecated or obsoleted upstream but never deleted, so the ingest pattern is
  pure UPSERT — no sweep is needed. `cwe.synced_at` is refreshed on every upsert.
- `cve_cwe.cwe_id` references `cwe.cwe_id` without a foreign key constraint, because
  sources occasionally cite ids outside the synced weakness set (categories, `CWE-NVD-*`
  pseudo-ids). In Hasura the `cve_cwe → cwe` join is configured as a manual relationship.
- Only the `json_repo/W/` subtree (Weaknesses) is sparse-checked out. Categories, Views,
  and CAPEC attack-pattern definitions in the same repo are not fetched.

---

## Schema coverage

```
cwe                ✅  full dictionary upsert (~940 weakness definitions)

cve_record         ❌  CVE List only
cve_desc           ❌
cve_cvss           ❌
cve_cwe            ❌  per-CVE weakness references come from other sources (cvelistv5, redhat, …)
cve_ref            ❌
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ❌
advisory_cve       ❌
cve_vendor         ❌
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
