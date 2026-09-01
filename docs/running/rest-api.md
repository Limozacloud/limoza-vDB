# REST API

A plain HTTP API for **batch** callers — a scanner or pipeline (e.g. Windmill) that posts
many components at once and gets matches back, with **no LLM and no per-call token cost**
(unlike the [MCP tools](mcp.md), which a model drives). It runs the same matcher core as
[`vdb match`](cli.md#match), served by the `api` container (`vdb api`).

Auth: a Bearer HS256 JWT — the same token [`vdb create-token`](cli.md#create-token) mints —
verified locally (no external call). `/match` accepts any valid token; `/lve` requires the
`lve_writer` role and `/curation` the `curation_writer` role.

## Endpoints

### `GET /healthz`
Liveness check → `ok`.

### `POST /match` — any valid token
Bulk version-check. Identical components are de-duplicated, so a scan with tens of
thousands of components is a single request. Matches include custom
[LVEs](../affected-versions.md#lve-custom-entries).

```json
{ "host": {
    "windows_product": "windows_server_2022",
    "windows_edition_id": "ServerStandard",
    "windows_installation_type": "Server",
    "architecture": "x64"
  },
  "components": [
  { "cpe": "cpe:2.3:o:microsoft:windows_server_2012:6.3.9600.20000:r2:*:*:*:*:*:*", "version": "6.3.9600.20000" },
  { "purl": "pkg:rpm/redhat/openssl", "version": "1.0.1e-30.el6_6.1", "release": "el6" },
  { "purl": "pkg:pypi/django", "version": "2.0" }
] }
```
→
```json
{ "total": 3, "vulnerable": 2, "compliant": 1, "unknown": 0,
  "results": [
    { "component": "…", "version": "…", "status": "vulnerable",
      "remediation": { "fixed": "3.0.21", "fix_kb": null, "cve": "CVE-2026-7383", "closes": 24, "unfixed": 0 },
      "cves": [ { "id": "CVE-…", "fixed": "…", "fix_kb": "KB5043050", "status": "fixed", "sources": ["microsoft"] } ] }
  ] }
```
Each component carries a `purl` and/or `cpe`, a `version`, and (for OS packages) a `release`.
Windows scans may supply one top-level `host` object and component `metadata` from Glance 0.9.1.
The matcher treats a real ecosystem purl as authoritative and does not retry it through an
arbitrary supplied CPE when it has no affected-version result: an empty result can mean the
component is known and compliant. A generic or absent purl uses the supplied CPE directly.
Reviewed compatibility aliases may map specific legacy identities to their canonical CPE after
the primary match finds nothing. `component` is the identity the matcher **resolved** (a purl or
a cpe — a generic purl loses to a real ecosystem purl or a cpe). `status` is `vulnerable` |
`compliant` | `unknown` (the
component couldn't be parsed/compared). For an applicable Microsoft CPE finding, `fix_kb` and
`source_fix_kb` carry the source MSRC article. This is not necessarily the package Windows Update
offers: cumulative and umbrella updates can use another KB. When product/platform/channel context
is incomplete, `selection` is `ambiguous`, both target fields are null, and `candidates` retains
the source evidence.

### Temporary legacy identity aliases

Until the next Glance release refreshes host inventory, `/match` also has a narrow compatibility
fallback for components that are **already present in the request** but have an older generic
PURL/name and no primary match. It never discovers a file or creates a host component.

| Existing identity | Temporary canonical CPE |
| --- | --- |
| `pkg:maven/log4j/log4j@<version>` or matching `log4j-<version>.jar` name | Apache Log4j |
| `pkg:generic/curl@<version>` or `curl.exe` | haxx curl |
| `pkg:generic/odbc-driver-sql-server@<version>` or `msodbcsql17.dll`/`msodbcsql18.dll` | Microsoft ODBC Driver for SQL Server |
| `pkg:generic/oledb-driver-sql-server@<version>` or `msoledbsql.dll` | Microsoft OLE DB Driver for SQL Server |

The response identifies a successful fallback in `identity_source`; values beginning with
`legacy_` are temporary compatibility mappings. They are retired after the matching Glance
release has produced canonical inventory identities across refreshed hosts.

For non-SQL components, `remediation` (present on vulnerable components) is the **single highest
fix** that closes the component's fixable CVEs — "upgrade to X → done":

| Field | Meaning |
|-------|---------|
| `fixed` | the version to upgrade to (the max fix across all the component's CVEs) |
| `fix_kb` | backward-compatible source MSRC KB, or `null` when ambiguous |
| `source_fix_kb` | source MSRC KB that establishes the fixed state |
| `selection` | `applicable` or `ambiguous` for context-sensitive Microsoft products |
| `cve` | the CVE that demands this highest version |
| `closes` | how many of the component's CVEs this upgrade closes |
| `unfixed` | CVEs with **no** fix available — an upgrade can't close these (so "closes" never over-promises) |

Example: a Windows host can return `{ "fixed": "10.0.20348.5256", "source_fix_kb": "KB5094128", "selection": "applicable", "closes": 2148, "unfixed": 0 }`.
Use Windows Update to select the currently applicable install package. `null` on compliant
components.

#### SQL Server GDR/CU tracks

SQL Server 2019 has verified parallel GDR (`15.0.2xxx` / `2019.150.2xxx`) and CU
(`15.0.4xxx` / `2019.150.4xxx`) servicing tracks. The requested or inferred track participates
in the vulnerability verdict itself: a CU host is not cleared merely because it exceeds a lower
GDR build. A caller may pass `"servicing_track": "gdr"` or `"cu"` on a SQL Server 2019
component. For a known non-RTM 2019 build, its inferred track takes precedence over a conflicting
request; a request selects the policy only when the 2019 build itself is ambiguous (RTM).
The remediation then exposes the selected track at the top level and both alternatives under
`by_track`:

```json
{
  "cpe": "cpe:2.3:a:microsoft:sql_server:15.0.2000.5:*:*:*:*:*:*:*",
  "version": "2019.150.2000.5",
  "servicing_track": "gdr"
}
```

```json
{
  "remediation": {
    "fixed": "2019.150.2180.2",
    "fix_kb": "KB5102336",
    "track": "gdr",
    "selection": "requested",
    "closes": 153,
    "unfixed": 1,
    "by_track": {
      "gdr": { "fixed": "2019.150.2180.2", "track": "gdr", "closes": 153, "unfixed": 1 },
      "cu": { "fixed": "15.0.4316.3", "track": "cu", "closes": 1, "unfixed": 153 }
    }
  }
}
```

RTM `15.0.2000.5` has not yet selected a servicing track. If no `servicing_track` is supplied,
the top-level remediation is intentionally `null`/`ambiguous` while `by_track` presents the two
separate paths. A CVE lacking a verified fix on a requested track is counted in that track's
`unfixed` value; the API does not assert cross-track equivalence without data for it. Other SQL
Server editions preserve parallel candidates in a vulnerable result but return an ambiguous
top-level remediation until vDB has a verified build-to-track classifier. Their vulnerability
verdict retains the historical parallel-fix behavior rather than applying unverified GDR/CU
classification rules.

### `POST /lve` — role `lve_writer`
Create a custom vulnerability entry ([LVE](../affected-versions.md#lve-custom-entries)).
A read-only token gets `403`.
```json
{ "product": "cpe:2.3:a:notepad-plus-plus:notepad++:*:*:*:*:*:*:*:*", "title": "Notepad++ < 8.7.4 RCE", "fixed": "8.7.4" }
```
→ `201 { "created": true, "id": "LVE-2026-0001", … }`. The new entry is matched immediately
(by this API, `vdb match`, and the MCP tools). Identify the product with a CPE 2.3 string or an
ecosystem/distro purl (rpm/deb/apk/pypi/npm/gem/golang/maven/cargo) — generic purls
(`pkg:generic/…`) are rejected, since they never match a scanned component.

### `POST /curation` — role `curation_writer`
Create a curation rule — a human correction/suppression applied at match time on top of the
synced data (the raw [affected](../affected-versions.md) rows stay intact). A rule targets a
`cve_id` and, via its optional selector (`coord`/`ecosystem`/`package`/`cpe23`/`release`/`source`),
a subset of that CVE's rows; `reason` is required, `created_by`/`expires_at` optional.
```json
{ "cve_id": "CVE-2026-48930", "action": "suppress",
  "source": "nvd", "cpe23": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
  "reason": "NVD enumeration incomplete; the nodejs range is authoritative", "created_by": "henrik" }
```
→ `201 { "created": true, "id": 7, … }`. `action` is `suppress` (drop the matched rows),
`set_status` (force a status → matcher skips it, but it stays visible with the reason), or
`set_fixed` (correct `fixed`/`introduced`/`last_affected`). A read-only token gets `403`.

### `GET /curation` — any valid token
List all curation rules.

### `POST /lve` and `POST /curation` can also run over [GraphQL](graphql.md)
via `insert_lve_one` / `insert_curation_one` with the same role — the REST endpoints and the
GraphQL mutations are two front doors to the same gated inserts.

## Run it
The `api` service ships in both compose files (`vdb api`; port 8770, behind Traefik in
production at `vdb-api.limoza.cloud`):
```bash
docker compose up -d api
```

## REST vs MCP — same data, different caller

| | REST (`/match`, `/lve`, `/curation`) | MCP (`match_bulk`, …) |
|--|--|--|
| Caller | a scanner / pipeline (curl, Windmill) | an LLM agent (Claude, …) |
| Cost | none — direct DB lookup | model tokens per call |
| Best for | large batches (10k+ components) | interactive, conversational checks |
| Writes | yes — LVE + curation (role-gated) | no — read-only |

Both share the matcher core and see the same data (including LVEs and curations). All writes
(LVEs, curations) go through REST (or the equivalent GraphQL mutations); the MCP server is
read-only.
