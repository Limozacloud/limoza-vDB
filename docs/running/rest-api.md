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
{ "components": [
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
Each component carries `purl` **or** `cpe`, a `version`, and (for OS packages) a `release`.
`component` is the identity the matcher **resolved** (a purl or a cpe — a generic purl loses
to a real ecosystem purl or a cpe). `status` is `vulnerable` | `compliant` | `unknown` (the
component couldn't be parsed/compared). For Microsoft CPE findings `fix_kb` carries the MSRC
KB article (e.g. `KB5043050`); it is `null` for distro/ecosystem sources.

`remediation` (present on vulnerable components) is the **single highest fix** that closes the
component's fixable CVEs — "upgrade to X → done":

| Field | Meaning |
|-------|---------|
| `fixed` | the version to upgrade to (the max fix across all the component's CVEs) |
| `fix_kb` | the KB shipping it (Windows) or `null` |
| `cve` | the CVE that demands this highest version |
| `closes` | how many of the component's CVEs this upgrade closes |
| `unfixed` | CVEs with **no** fix available — an upgrade can't close these (so "closes" never over-promises) |

Example: a Windows host → `{ "fixed": "10.0.20348.5256", "fix_kb": "KB5094128", "closes": 2148, "unfixed": 0 }`
("install KB5094128 → 2148 CVEs closed"). `null` on compliant components.

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
