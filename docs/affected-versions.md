# Affected versions (L4)

The [advisory tiers](advisory-tiers.md) answer *who* is affected (CNA, upstream,
downstream). **L4** answers *which versions* — the precise affected / fixed ranges per
package, so a scanned system can be version-compared against the database: "is *this*
build of *this* product actually vulnerable, or already patched?"

All of it lives in one table, `affected`, derived by a central pass (`vdb affected`)
that runs once after sync + ingest.

## Two coordinate systems

Software identity comes in two shapes, so each `affected` row is keyed by one of two
**coordinates**:

| `coord` | For | Identity | Examples |
|---------|-----|----------|----------|
| `purl` | managed / ecosystem software | package URL | `pkg:rpm/redhat/openssl`, `pkg:deb/ubuntu/curl`, `pkg:pypi/django`, `pkg:npm/undici` |
| `cpe` | unmanaged / binary / OS software | CPE 2.3 `vendor:product` | Windows, Microsoft products, vendor binaries (`cpe:2.3:o:microsoft:windows_server_2012`) |

The `purl` lane carries a distro `release` (el9, jammy, …); the `cpe` lane is
release-agnostic and compares build numbers.

## Row shape

OSV-style ranges in either coordinate:

| Column | Description |
|--------|-------------|
| `cve_id` | the CVE |
| `coord` | `purl` \| `cpe` |
| `ecosystem` / `package` / `release` | purl-lane identity (rpm/deb/pypi/…, name, distro release) |
| `cpe23` | cpe-lane identity — canonical 13-field `vendor:product` (see [CPE validation](#cpe-validation)) |
| `introduced` / `fixed` / `last_affected` | the version range (fixed = exclusive upper, last_affected = inclusive) |
| `fix_kb` | remediation reference for the fix — a Microsoft MSRC KB (e.g. `KB5043050`); NULL for other sources |
| `version_scheme` | how to compare (`rpm`, `deb`, `semver`, `pep440`, `generic`, …) |
| `status` | canonical VEX status (below) |
| `status_raw` | the source's original wording, kept for audit |
| `source` / `status_source` / `origin` | provenance (author / who decided / importer) |

### Canonical status

Every source's native vocabulary is mapped onto six values that drive the matcher:

| Status | Meaning |
|--------|---------|
| `not_affected` | explicitly not affected → suppressed |
| `under_investigation` | being assessed → not flagged |
| `affected` | vulnerable, no fix yet → flagged |
| `fixed` | fixed in a version → flagged only if installed `<` fixed |
| `wont_fix` | vendor won't fix (Debian no-dsa / `unimportant` / EOL, Ubuntu EOL, …) → **excluded from the vulnerable verdict**, kept in the DB with its `justification` for audit |
| `unknown` | no statement → grey zone |

The matcher suppresses `not_affected`, `under_investigation`, `unknown` **and** `wont_fix`
— so a deprioritised finding stays queryable (with the reason in `justification`) but does
not count as vulnerable. `affected` and `fixed` (when installed `<` fixed) are the only
statuses that flag.

## How it's derived

`vdb affected` runs per-source extractors; each owns its slice (delete-by-`origin`,
reinsert). Sources:

- **Distros (purl):** Red Hat, SUSE, Ubuntu, Debian, Oracle — from their VEX/OVAL/tracker
  data. Debian (no-dsa / `urgency`) and Ubuntu (OpenVEX action statements) map their
  deprioritised CVEs to `wont_fix` with a `justification`; Red Hat carries it natively in
  its CSAF remediations.
- **Clones (purl):** AlmaLinux, Rocky, Oracle Linux inherit Red Hat's ranges
  (`status_source = redhat-inherited`) so a clone host matches even when the clone
  filed no advisory of its own.
- **Ecosystems (purl):** GHSA + OSV-native, from the per-package version ranges.
- **NVD (cpe):** the **authoritative** CPE lane — `configurations[].cpeMatch` version
  ranges, see [NVD](datasources/nvd.md).
- **CVE List (cpe):** CPE synthesis for CVEs NVD has no configuration for, **and** name-only
  CNA affected entries (no `cpes` field) resolved through a curated `(vendor,product)→CPE`
  map — this lands the real per-branch backport fixes that NVD collapses into a single
  mainline fix (e.g. PSF/CPython: `< 3.13.14` per line, not just `fixed 3.15.0`). See
  [CVE List](datasources/cvelistv5.md).
- **Microsoft (cpe):** MSRC fix builds, each carrying its KB in `fix_kb` — see
  [Microsoft](datasources/microsoft.md).
- **Node.js (cpe):** per-release-line ranges for the Node.js runtime
  (`cpe:2.3:a:nodejs:node.js`) from `nodejs/security-wg`, which NVD only enumerates as sample
  versions and GHSA/OSV don't carry (node core is not an npm package). See
  [Node.js](datasources/nodejs.md).

## CPE validation

Every CPE we store is resolved and **validated against the NVD CPE dictionary** (the
`cpe` table) by `ingest/affected/cpe_norm.py`, so a stored row and a scanned component
always land on the same key:

- **Candidate + validate.** MSRC and NVD encode the same product differently — MSRC
  puts "R2" in the product name (`windows_server_2012_R2`), NVD in the update field
  (`windows_server_2012` + `update=r2`). `cpe_norm` generates candidate
  `(vendor, product, update)` tuples and keeps the one NVD actually contains. Both forms
  resolve to the same canonical key, while plain 2012 vs 2012 R2 stay distinct (own
  builds 6.2.9200 vs 6.3.9600).
- **Canonical form.** 13-field, lowercase, `cpe:2.3:part:vendor:product:*:update:*…`.
- **Strict.** A CPE whose `(vendor, product)` isn't in the catalogue is **dropped** — we
  only store CPEs a scanner can actually produce.
- **Name fallback.** Older MSRC products carry no CPE; `from_name()` derives one from the
  product name and validates it the same way.

## LVE (custom entries)

**Local Vulnerability Entries** are your own vuln records for things not in any public
feed (e.g. "Notepad++ < 8.7.4"). They live in the `lve` table — the source of truth — and
are **matched exactly like a CVE**:

- An `AFTER` trigger materialises each `lve` row into `affected` (`origin='lve'`,
  `cve_id` = the LVE id) **immediately**, so a new entry matches at once.
- The `lve` affected-extractor re-seeds those rows on every `vdb affected` run, so they
  **survive any truncate/rebuild** — re-derived from the `lve` table, like a distro's rows
  from `/data`.
- The matcher needs no special case — LVEs are ordinary `affected` rows.

Create one via the REST [`POST /lve`](running/rest-api.md) or the `insert_lve_one`
[GraphQL](running/graphql.md) mutation — both require an `lve_writer`
[token](running/cli.md#create-token). Ids are `LVE-YYYY-NNNN`. Identify the product with a
CPE or an ecosystem/distro purl; a generic purl (`pkg:generic/…`) is rejected, since it never
matches a scanned component.

## Curation (match-time overrides)

When a source is wrong for our purposes, a **curation** rule corrects it without touching the
raw data. Rules live in the `curation` table (never touched by sync, survives rebuilds like
`lve`) and are applied by the matcher *after* it fetches the affected rows — so the upstream
data stays intact for audit ("NVD says X, we override to Y because *reason*"). A rule targets
a `cve_id` and, via its non-NULL selector (`coord`/`ecosystem`/`package`/`cpe23`/`release`/`source`),
a subset of that CVE's rows:

- **`suppress`** — drop the matched rows (a false positive / not-applicable finding).
- **`set_status`** — force a status (`wont_fix`/`not_affected` → the matcher skips it, but it
  stays visible in GraphQL with the reason).
- **`set_fixed`** — correct the `fixed`/`introduced`/`last_affected` bound.

`reason` is required; `expires_at` gives optional auto-expiry. Create one via the REST
[`POST /curation`](running/rest-api.md) or the `insert_curation_one`
[GraphQL](running/graphql.md) mutation — both require a `curation_writer`
[token](running/cli.md#create-token).

## The matcher

The shared matcher (`ingest/match`) holds a scanned component against `affected`,
exposed as the [`vdb match`](running/cli.md#match) CLI and the
[`check_vulnerable`](running/mcp.md#tools) MCP tool.

- **purl input** → ecosystem + release lookup, version-compared with
  [`univers`](https://github.com/aboutcode-org/univers) per scheme. For deb the **source**
  package (the `upstream` qualifier, falling back to the purl name) and the release
  codename (`distro=debian-11` → `bullseye`, `ubuntu-22.04` → `jammy`, …) drive the lookup.
- **cpe input** → `vendor:product(+update)` lookup. The `generic` scheme compares with
  `univers`' `MavenVersion`, so numeric parts rank numerically (17.9 < 17.10, Windows UBRs)
  and letter versions work (openssl 1.1.1w < 1.1.1x). Findings are aggregated per
  `(cve, product)`: a host is patched once it reaches **any** fix build of that CVE/product,
  so parallel fix tracks (Windows security-only vs monthly rollup) never false-positive.
- **curation** → after the affected rows are fetched, any matching
  [curation](#curation-match-time-overrides) rule is applied per row (suppress / set_status /
  set_fixed) before the verdict, so overrides always take effect without altering the raw data.

Each finding carries the `fixed` version and, for Microsoft CPE hits, the `fix_kb` (MSRC KB).

```bash
vdb match pkg:rpm/redhat/openssl@1.0.1e-30.el6_6.1
vdb match 'cpe:2.3:o:microsoft:windows_server_2012:6.3.9600.20000:r2:*:*:*:*:*:*'
```

## Querying it

`affected` is tracked in Hasura (related from `cve`), so it is one GraphQL query:

```graphql
query Affected($cve: String!) {
  affected(where: { cve_id: { _eq: $cve } },
           order_by: [{ status: asc }, { package: asc }, { release: asc }]) {
    coord ecosystem package release cpe23
    status introduced fixed last_affected version_scheme source
  }
}
```

A CVE can legitimately return **no** `affected` rows — e.g. a cloud-service CVE (no
installable version to compare) still has advisory tiers but nothing to match.
