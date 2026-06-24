# REST API

A plain HTTP API for **batch** callers — a scanner or pipeline (e.g. Windmill) that posts
many components at once and gets matches back, with **no LLM and no per-call token cost**
(unlike the [MCP tools](mcp.md), which a model drives). It runs the same matcher core as
[`vdb match`](cli.md#match), served by the `api` container (`vdb api`).

Auth: a Bearer HS256 JWT — the same token [`vdb create-token`](cli.md#create-token) mints —
verified locally (no external call). `/match` accepts any valid token; `/lve` requires the
`lve_writer` role.

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
      "cves": [ { "id": "CVE-…", "fixed": "…", "status": "fixed", "sources": ["microsoft"] } ] }
  ] }
```
Each component carries `purl` **or** `cpe`, a `version`, and (for OS packages) a `release`.
`status` is `vulnerable` | `compliant` | `unknown` (the component couldn't be parsed/compared).

### `POST /lve` — role `lve_writer`
Create a custom vulnerability entry ([LVE](../affected-versions.md#lve-custom-entries)).
A read-only token gets `403`.
```json
{ "product": "pkg:generic/notepad++", "title": "Notepad++ < 8.7.4 RCE", "fixed": "8.7.4" }
```
→ `201 { "created": true, "id": "LVE-2026-0001", … }`. The new entry is matched immediately
(by this API, `vdb match`, and the MCP tools).

## Run it
The `api` service ships in both compose files (`vdb api`; port 8770, behind Traefik in
production at `vdb-api.limoza.cloud`):
```bash
docker compose up -d api
```

## REST vs MCP — same data, different caller

| | REST (`/match`, `/lve`) | MCP (`match_bulk`, `create_lve`) |
|--|--|--|
| Caller | a scanner / pipeline (curl, Windmill) | an LLM agent (Claude, …) |
| Cost | none — direct DB lookup | model tokens per call |
| Best for | large batches (10k+ components) | interactive, conversational checks |

Both share the matcher core and see the same data (including LVEs).
