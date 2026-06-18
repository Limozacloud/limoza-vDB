# GraphQL & Hasura

[Hasura GraphQL Engine](https://hasura.io/) sits on top of PostgreSQL and exposes the
LVE schema as a GraphQL API — no resolver code to write, the API is generated from the
tables and relationships.

| Endpoint | URL |
|----------|-----|
| GraphQL | `http://localhost:8080/v1/graphql` |
| Console | `http://localhost:8080/console` |

The Hasura service is configured in `docker-compose.yml` and reads
`HASURA_ADMIN_SECRET` and `HASURA_JWT_SECRET` from `.env`.

## Custom Hasura build

The Compose files use `ghcr.io/mchill007/graphql-engine` — a fork of Hasura GraphQL
Engine **Community Edition** (Apache-2.0), not the stock `hasura/graphql-engine` image.

The fork adds `_any` and `_all` filter operators for **element-level pattern matching on
string-array columns**. Stock Hasura only supports whole-value matching on arrays
(`_contains: ["exact"]`), but limoza-vDB stores identifiers in the `lve.aliases` `TEXT[]`
column and needs to match individual elements — e.g. "every LVE whose aliases contain an
advisory starting with `ADV`":

```graphql
query AdvAliases {
  lve(where: { aliases: { _any: { _ilike: "ADV%" } } }) {
    lve_id
    aliases
  }
}
```

- `_any: { <op>: <value> }` — true if **at least one** array element matches
- `_all: { <op>: <value> }` — true if **all** elements match

Supported inner operators include `_eq`, `_like`, `_ilike`, `_regex`, `_iregex` (and
their negations). The operators work on `text[]`, `varchar[]`, `citext[]`, and `char[]`
columns. They are community-edition server features and remain under Apache-2.0; the
changes are tracked in the fork's
[PR #1](https://github.com/McHill007/graphql-engine/pull/1) and
[PR #2](https://github.com/McHill007/graphql-engine/pull/2).

!!! note "Using stock Hasura instead"
    You can run the upstream `hasura/graphql-engine` image, but queries that use
    `_any` / `_all` on array columns will not be available — filter such columns
    client-side instead.

## One-time setup: `hasura-init`

A fresh Hasura instance knows nothing about the tables. Run this once after the first
`import`:

```bash
docker compose run --rm ingest hasura-init
```

It performs three things:

1. **Tracks** every table — `lve`, `lve_cve`, `notices`, and all child tables
   (`lve_titles`, `lve_descriptions`, `lve_cvss`, `lve_cwes`, `lve_references`,
   `lve_advisories`, `lve_upstream`, `lve_packages`, `lve_mitigations`, `lve_impacts`,
   `lve_exploits`, `lve_history`).
2. **Builds relationships** so the whole record can be fetched in one query:
   `lve` ↔ `lve_cve` (object), `lve` → each child table (array), and each child → `lve`
   (object).
3. **Grants the `readonly` role** SELECT-only access (with aggregations) on every table.

It is idempotent — already-tracked tables and existing relationships are skipped, so you
can re-run it safely after schema changes.

## Roles

| Role | Access |
|------|--------|
| `admin` | Full access via `X-Hasura-Admin-Secret` (the console). Keep the secret private. |
| `readonly` | SELECT-only on all tables. Granted to JWT-authenticated API consumers. |
| `anonymous` | The unauthorized role (`HASURA_GRAPHQL_UNAUTHORIZED_ROLE`) for requests without a token. |

## Read-only tokens

External API consumers authenticate with a short-lived, read-only JWT. Mint one with
`create-token` (it signs with `HASURA_JWT_SECRET`, which must match the key Hasura was
started with):

```bash
# Generate a signing key once and add it to .env
echo "HASURA_JWT_SECRET=$(openssl rand -hex 32)" >> .env

# Mint a token (default TTL 1 day; --ttl sets days)
docker compose run --rm ingest create-token --ttl 90
```

Pass it as a bearer token:

```
Authorization: Bearer <token>
```

The token carries the `readonly` Hasura role, so it can only run SELECT queries.

## Querying

Use the console's GraphiQL explorer, or POST to the endpoint. Ready-to-run queries —
including a full single-CVE scan and a package-vulnerability lookup — are in
[GraphQL example queries](../graphql-example-queries.md).
