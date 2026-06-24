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
| `wont_fix` | vulnerable, no fix coming → flagged (labelled) |
| `unknown` | no statement → grey zone |

## How it's derived

`vdb affected` runs per-source extractors; each owns its slice (delete-by-`origin`,
reinsert). Sources:

- **Distros (purl):** Red Hat, SUSE, Ubuntu, Debian, Oracle — from their VEX/OVAL/tracker data.
- **Clones (purl):** AlmaLinux, Rocky, Oracle Linux inherit Red Hat's ranges
  (`status_source = redhat-inherited`) so a clone host matches even when the clone
  filed no advisory of its own.
- **Ecosystems (purl):** GHSA + OSV-native, from the per-package version ranges.
- **CVE List (cpe):** CNA-provided CPEs in `containers.cna.affected[].cpes`.
- **Microsoft (cpe):** MSRC fix builds — see [Microsoft](datasources/microsoft.md).

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

Create one via the REST [`POST /lve`](running/rest-api.md) or the MCP
[`create_lve`](running/mcp.md#tools) tool — both require an `lve_writer`
[token](running/cli.md#create-token). Ids are `LVE-YYYY-NNNN`.

## The matcher

The shared matcher (`ingest/match`) holds a scanned component against `affected`,
exposed as the [`vdb match`](running/cli.md#match) CLI and the
[`check_vulnerable`](running/mcp.md#tools) MCP tool.

- **purl input** → ecosystem + release lookup, version-compared with
  [`univers`](https://github.com/aboutcode-org/univers) per scheme.
- **cpe input** → `vendor:product(+update)` lookup, numeric build compare. Findings are
  aggregated per `(cve, product)`: a host is patched once it reaches **any** fix build of
  that CVE/product, so parallel fix tracks (Windows security-only vs monthly rollup) never
  false-positive.

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
