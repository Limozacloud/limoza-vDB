# GraphQL & Hasura

[Hasura](https://hasura.io/) serves the database as a **read-only** GraphQL API.
There are no foreign keys in the schema, so the relationships between the `cve` spine
and its child tables are wired explicitly during setup.

## Endpoint

```
POST  http://localhost:8080/v1/graphql
```

Every request must carry a read-only bearer token:

```
Authorization: Bearer <token>
```

The Hasura console (dev only) is at `http://localhost:8080/console`.

## One-time setup

After the first `ingest`, run [`hasura-init`](cli.md#hasura-init):

```bash
docker compose exec ingest vdb hasura-init
```

It is idempotent and does four things:

1. **Tracks** every table so it becomes a GraphQL type.
2. **Wires relationships** manually (`manual_configuration`, since there are no FKs):
   the `cve` spine to its `cve_record`, `cve_cvss`, `cve_cwe`, `cve_desc`, `cve_ref`,
   … rows; `advisory` ↔ `advisory_cve`; `cve_cwe` → the `cwe` dictionary; and so on.
3. **Tracks the `cve_levels` function** so the [advisory tiers](../advisory-tiers.md)
   are a GraphQL root field.
4. **Grants** SELECT on everything to the `readonly`, `lve_writer` and `curation_writer`
   roles, plus INSERT on `lve` (to `lve_writer`) and on `curation` (to `curation_writer`).

## Permissions

Three roles exist. **`readonly`** can run SELECT queries and nothing else — it sees no
mutations at all. **`lve_writer`** and **`curation_writer`** additionally get one insert:
`insert_lve_one` / `insert_lve` and `insert_curation_one` / `insert_curation` respectively
(no update or delete — those need the admin secret). There is no anonymous access; an
unauthenticated request is rejected. The Hasura admin secret is for setup only and is never
handed to API consumers. Curation rules are related from the spine as `cve.curations`, so a
CVE's overrides are one traversal away.

## Read-only tokens

API access uses an HS256 JWT signed with the shared `HASURA_JWT_SECRET`, carrying the
`readonly` role (or a write role). Mint one with [`create-token`](cli.md#create-token):

```bash
docker compose exec ingest vdb create-token --ttl 90                           # read-only
docker compose exec ingest vdb create-token --role lve_writer,curation_writer  # + both writes
```

`--role` takes one or several comma-separated roles; `readonly` is always included and the
first role is the default. The read-only token's claims pin the role:

```json
{
  "https://hasura.io/jwt/claims": {
    "x-hasura-allowed-roles": ["readonly"],
    "x-hasura-default-role": "readonly"
  }
}
```

Send it as `Authorization: Bearer <token>`. Tokens expire (default 1 day) — mint a
longer-lived one for an application with `--ttl`.

## Querying

```bash
curl -s http://localhost:8080/v1/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ cve(limit:5){ cve_id first_seen } }"}'
```

A CVE's full picture is one query joining the spine to its child rows; the tiered
advisory view is the `cve_levels` field. See [GraphQL example queries](../graphql-example-queries.md)
and [Advisory tiers (L1–L3)](../advisory-tiers.md).
