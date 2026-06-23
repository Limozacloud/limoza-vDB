# limoza-vDB

A CVE-centric vulnerability aggregation system. limoza-vDB syncs CVE and advisory
data from 20+ upstream sources, stores each source's contribution **side by side**
in PostgreSQL keyed by CVE id, and exposes everything through a read-only GraphQL API.

## How it works

```
            sync                 transform              write
 source ─────────────▶ /data/<source> ─────▶ rows (per source) ─────▶ PostgreSQL ─────▶ Hasura GraphQL
 feeds                  (local volume)        (ingest/)                (schema.sql)      (read-only API)
```

1. **[Sync](ingest/index.md)** — download raw data from each source into local volumes.
2. **Transform** — each source module maps its format onto the shared tables.
3. **Write** — each source inserts its own rows; nothing is merged or overwritten.
4. **Serve** — Hasura exposes the schema as GraphQL with a read-only role.

## The central idea

The **CVE id is the only join key**. There is no synthetic identifier and no
single merged record per vulnerability. Instead:

- a thin `cve` spine registers every CVE id anyone has ever mentioned;
- each source writes into its own rows, tagged with where the data came from;
- a CVE's full picture is assembled at query time by joining on `cve_id`.

Because no source owns the shared rows, imports are **order-independent** and run
without lock contention — one source failing never blocks the others.

On top of that, the [advisory tiers](advisory-tiers.md) model answers a practical
question for any CVE: *who assigned it (L1), what does the affected product's own
advisory say (L2), and which downstream distros / ecosystems shipped a fix (L3)?*

## Where to go next

- **[Pipeline overview](ingest/index.md)** — how sync, transform, and write fit together.
- **[Data model](ingest/schema.md)** — the tables every source writes into.
- **[Data sources](datasources/index.md)** — per-source feeds, field mappings, and schema coverage.
- **[Advisory tiers (L1–L3)](advisory-tiers.md)** — the tiered advisory view for one CVE.
- **[GraphQL examples](graphql-example-queries.md)** — ready-to-run queries.
- **[MCP server](running/mcp.md)** — Model Context Protocol server for LLM clients.
- **[Documentation conventions](datasource_blueprint.md)** — how to document a new source.

For installation and the full CLI reference, see [Running limoza-vDB](running/docker.md).

> **License:** limoza-vDB is source-available under
> [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0) —
> free for noncommercial use, modification, and distribution.
