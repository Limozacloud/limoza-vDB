# Data model

The canonical, machine-readable definition is `schema.sql` (repository root). The
sections below are the human-readable reference — when in doubt, `schema.sql` is
authoritative.

The design is **CVE-centric**: the CVE id is the only join key, there is no
synthetic identifier, and every source writes into its own rows. There are no
foreign keys — `cve_id` joins everything, and a `CHECK` constraint keeps it in
canonical form. A vulnerability's full picture is assembled at query time.

Two data shapes recur:

1. **CVE-keyed rows** — one or many rows per CVE (`cve_record`, the `cve_*`
   enrichment tables, `epss`, `kev`, `ssvc`, `exploits`, `advisory_cve`,
   `cve_vendor`).
2. **Standalone dictionaries** — keyed by their own id (`cna`, `adp`, `cpe`,
   `cwe`, `source_url`).

??? note "Full schema (`schema.sql`)"

    ```sql
    --8<-- "schema.sql"
    ```

---

## The CVE spine

### `cve`

A thin, shared registry of every CVE id anyone has mentioned. Created by **any**
source that references a CVE (`ON CONFLICT DO NOTHING`) — nobody owns it.

| Column | Type | Description |
|--------|------|-------------|
| `cve_id` | text PK | canonical id, `CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]+$')` |
| `first_seen` | timestamptz | when the id first entered the database |

A `cve` row with no matching `cve_record` means "known to some source, not yet
published in the CVE List".

### `cve_record`

The CVE List baseline — one row per CVE, written by [CVE List](../datasources/cvelistv5.md).

| Column | Type | Description |
|--------|------|-------------|
| `cve_id` | text PK | |
| `state` | text | `PUBLISHED` \| `REJECTED` \| `RESERVED` |
| `assigner` | text | the assigning CNA's short name → `cna.short_name` (the **L1** tier) |
| `date_reserved` / `date_published` / `date_updated` | timestamptz | lifecycle dates |
| `title` | text | CNA-provided title |
| `exploit_note` | text | CNA prose about exploitation |

---

## Per-CVE enrichment (multi-source)

These tables hold the descriptive content of a CVE. Each has the same provenance
columns — **`origin`** (the importer, the unit of delete-and-replace) and
**`source`** (who authored the data: `cna`, an ADP short name, a distro, …)
— so several sources contribute side by side without overwriting each other.

| Table | Holds | Key columns |
|-------|-------|-------------|
| `cve_cvss` | CVSS scores | `version`, `base_score`, `severity`, `vector` |
| `cve_cwe` | CWE weakness ids | `cwe_id` → [`cwe`](../datasources/cwe.md) |
| `cve_desc` | descriptions | `lang`, `value` |
| `cve_ref` | references / links | `url`, `type` |
| `cve_solution` | remediation prose | `lang`, `value` |
| `cve_workaround` | mitigation prose | `lang`, `value` |
| `cve_impact` | CAPEC impact | `capec_id`, `description` |
| `cve_alias` | other ids (GHSA, JVNDB, …) | `alias` |

Each is uniquely keyed by `(cve_id, origin, source, …)` so re-imports are
idempotent.

---

## Advisories

Vendor and distro security **bulletins** (RHSA, USN, GHSA, …). The issuer's own
per-CVE enrichment lands in the `cve_*` tables (with `origin = <source>`); only the
bulletin object, its CVE links, and the per-CVE vendor assessment live here.

### `advisory`

| Column | Type | Description |
|--------|------|-------------|
| `source` | text | the **issuer** name (`redhat`, `suse`, `ghsa`, …) — not always a CNA |
| `advisory_id` | text | `RHSA-2024:2011` |
| `url`, `title`, `severity` | text | per-advisory metadata (may be NULL) |
| `published` / `modified` | timestamptz | |
| `vendor_data` | jsonb | source-specific extras |

Primary key `(source, advisory_id)`.

### `advisory_cve`

Links `(source, advisory_id)` to one or more `cve_id`. The many-to-many between
bulletins and CVEs.

### `cve_vendor`

A per-CVE **assessment** by a vendor/distro — present even when no formal bulletin
was issued (e.g. a distro that only tracks a CVE's status). One row per
`(cve_id, source)`; everything source-specific lives in `data` (JSONB), typically a
severity/priority/urgency.

> The split matters for the [advisory tiers](../advisory-tiers.md): a formal
> `advisory` is a published bulletin, while a `cve_vendor` row with no advisory is a
> distro that merely *tracked* the CVE.

---

## Dictionaries

### `cna`

CVE Numbering Authorities (from the CVE Program partner list).

| Column | Type | Description |
|--------|------|-------------|
| `short_name` | text PK | the assigner name used by `cve_record.assigner` |
| `cna_id`, `organization_name`, `scope`, `advisory_url` | text | partner metadata |
| `aliases` | text[] | record short-name variants that map to this CNA |
| `uuids` | text[] | all `providerMetadata.orgId`s seen → join key for `cve_*.source` |
| `advisory_patterns` | jsonb | `[{pattern, template}]` — drives the **L2** upstream-advisory match |
| `active` | boolean | soft-delete flag (CNAs are never hard-deleted) |

### `adp`

Authorized Data Publishers (CISA-ADP, the CVE Program container, …) — collected as
a byproduct of the CVE List scan. `cve_*.source` references these by UUID for
ADP-authored rows.

### `cpe`

The NVD CPE 2.3 dictionary (~1.7M entries) — used to validate product identifiers.

### `cwe`

CWE weakness definitions (~940 rows) — the dictionary `cve_cwe.cwe_id` joins to.

---

## Risk scoring

One row per CVE, each a full snapshot from its source:

| Table | Source | Holds |
|-------|--------|-------|
| `epss` | [FIRST EPSS](../datasources/epss.md) | `score`, `percentile`, `date` |
| `kev` | [CISA KEV](../datasources/cisa-kev.md) | known-exploited metadata, ransomware flag, due date |
| `ssvc` | [CISA SSVC](../datasources/cisa-ssvc.md) | `exploitation`, `automatable`, `technical_impact` |

---

## Exploit intelligence

### `exploits`

Four homogeneous sources (`exploitdb`, `metasploit`, `nuclei`, `poc_github`) share
one table with a `source` column. Per-source extras live in `metadata` (JSONB).
Only a **link** plus factual metadata is stored — never an exploit body.

> "Does this CVE have an exploit?" = `EXISTS (SELECT 1 FROM exploits WHERE cve_id = …)`.

---

## Advisory tiering

### `source_url`

Per-source URL templates (`cve_url`, `advisory_url`, `when_id_prefix`) — the
SQL-accessible mirror of `ingest/advisories/source_urls.json`, the editable single
source of truth. Seeded by `vdb ingest source_urls`.

### `cve_level` & `cve_levels(cve)`

`cve_levels(cve)` is a set-returning function that assembles the tiered advisory
view (L1 CNA / L2 upstream / L3 downstream) for one CVE, using `source_url` so it
needs no hardcoded links. Tracked in Hasura as a GraphQL field. See
[Advisory tiers (L1–L3)](../advisory-tiers.md).

---

## Affected versions (L4)

### `affected`

The version-precise layer derived by the `vdb affected` pass — one row per
(CVE, package/product, range), in two coordinate systems. See
[Affected versions (L4)](../affected-versions.md).

| Column | Type | Description |
|--------|------|-------------|
| `cve_id` | text | the CVE |
| `coord` | text | `purl` (managed / ecosystem) \| `cpe` (unmanaged / OS / binary) |
| `ecosystem` / `package` / `release` | text | purl-lane identity (rpm/deb/pypi/…, name, distro release) |
| `cpe23` | text | cpe-lane identity — canonical, NVD-validated `vendor:product` |
| `introduced` / `fixed` / `last_affected` | text | the version range (fixed = exclusive, last_affected = inclusive) |
| `fix_kb` | text | remediation reference for the fix — a Microsoft MSRC KB (e.g. `KB5043050`); NULL for distro/ecosystem sources |
| `version_scheme` | text | comparison scheme (`rpm`, `deb`, `semver`, `pep440`, `generic`, …) |
| `status` | text | canonical VEX status (`not_affected` / `under_investigation` / `affected` / `fixed` / `wont_fix` / `unknown`) |
| `status_raw` | text | the source's original wording |
| `justification` | text | why the status was derived (e.g. `urgency: unimportant`, `nodsa: ignored`) — surfaced by `explain_status` |
| `source` / `status_source` / `origin` | text | author / who decided / importer (delete-scope key) |

Tracked in Hasura (related from `cve`); the
[matcher](../affected-versions.md#the-matcher) version-compares a scanned component
against it (`vdb match`, MCP `check_vulnerable`).

### `lve`

User-defined vulnerability entries ([LVE](../affected-versions.md#lve-custom-entries)) —
the source of truth for vulns not in any public feed. Same shape as `affected` (id =
`LVE-YYYY-NNNN`, plus `title` / `description` / `severity` / `created_by`). An `AFTER`
trigger (`lve_sync`) materialises each row into `affected` (`origin='lve'`) immediately,
and the `lve` affected-extractor re-seeds it on every rebuild — so LVEs survive a
truncate. Insert is gated by the `lve_writer` Hasura role. `ecosystem` cannot be `generic`
(`CHECK (ecosystem IS DISTINCT FROM 'generic')`) — a generic purl never matches a scanned
component, so the product must be identified by a CPE or an ecosystem/distro purl.

### `curation`

Human corrections/suppressions applied at **match time** — for when a source is wrong for
our purposes. Never touched by sync (survives every rebuild, like `lve`), and applied by the
[matcher](../affected-versions.md#the-matcher) *after* it fetches the affected rows, so the
raw upstream data stays intact for audit. Each rule targets a `cve_id` and, via its non-NULL
selector fields (`coord` / `ecosystem` / `package` / `cpe23` / `release` / `source`), a subset
of that CVE's rows:

| `action` | Effect |
|----------|--------|
| `suppress` | the matched rows are dropped (a false positive / not-applicable finding) |
| `set_status` | force a status (e.g. `wont_fix` / `not_affected` → the matcher skips it, but it stays visible in GraphQL with the reason) |
| `set_fixed` | correct the `fixed` / `introduced` / `last_affected` bound |

`reason` is required; `created_by` / `expires_at` (auto-expiry) optional. Tracked in Hasura and
related from `cve` as `curations`; insert is gated by the `curation_writer` role. Created via
`POST /curation` or the `insert_curation_one` GraphQL mutation.

---

## Operations

### `sync_log`

One row per sync/ingest run per source — `status` (`success` / `no_new_data` /
`failed`), item counts, row deltas, timing, and a message. Powers the dashboard's
freshness ("last successful X") and error views. The "latest run per source" is a
query (`DISTINCT ON (source, phase) … ORDER BY finished_at DESC`).
