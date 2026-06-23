# CNA directory

The CNA directory is a reference dictionary of CVE Numbering Authorities — the
organizations that assign CVE ids. It is what `cve_record.assigner` resolves to, and
it carries the patterns that drive the upstream [advisory tier](../advisory-tiers.md).

## Feed
- **URL:** `https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json`
- **Official:** Yes — the CVE Program partner list
- **Format:** JSON (one entry per CNA)
- **Local path:** `cnas.json`
- **Content:** short name, organization, scope, and advisory URL per CNA

Two further inputs are bundled with the importer:

- **`cna_mapping.json`** — curated supplements: record short-name aliases that drift
  from the canonical name, plus rows for orgs missing from the official list.
- **`cna_advisory_patterns.json`** — manual overrides for the advisory patterns
  described below.

## What it writes

The `cna` dictionary table:

| Column | From |
|--------|------|
| `short_name`, `cna_id`, `organization_name`, `scope`, `advisory_url` | the partner list |
| `aliases` | record short-name variants → this CNA (from `cna_mapping.json`) |
| `uuids` | every `providerMetadata.orgId` seen in the [CVE List](cvelistv5.md) corpus — the join key for `cve_*.source` |
| `advisory_patterns` | `[{pattern, template}]` — derived + overridden (see below) |
| `active` | soft-delete flag |

**Pattern:** official rows are upserted with a soft sweep (a CNA dropped from the
list is marked `active = false`, never hard-deleted); aliases are rebuilt from the
mapping each run.

## Advisory patterns (L2)

Many products are their own CNA (OpenSSL, curl, the Linux kernel, …) and publish
their own advisories. `advisory_patterns` captures, per CNA, the URL pattern of those
advisories — derived automatically from the dominant reference host that CNA uses
across its CVEs, then refined by `cna_advisory_patterns.json` overrides.

`cve_levels()` uses these patterns to find the **L2 upstream** advisory: a CVE List
reference matching a CNA's pattern is that product's own advisory. See
[Advisory tiers (L1–L3)](../advisory-tiers.md).

---

## Schema coverage

```
cna                ✅  the dictionary (incl. uuids + advisory_patterns)
everything else    ❌  reference data only — writes no per-CVE rows
```
