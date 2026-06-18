# limoza-vDB

A multi-vendor vulnerability aggregation system. limoza-vDB syncs CVE and advisory
data from 20+ upstream sources, normalizes everything into a single unified schema
(the **LVE record**), stores it in PostgreSQL, and exposes it through a read-only
GraphQL API.

## How it works

```
            sync                transform              upsert
 vendor ─────────────▶ /data/<vendor> ─────▶ LVE record ─────▶ PostgreSQL ─────▶ Hasura GraphQL
 feeds                  (local volume)        (ingest/)         (schema.sql)      (read-only API)
```

1. **[Sync](ingest/index.md)** — download raw data from each source into local volumes.
2. **Transform** — each vendor module maps its source format onto the common schema.
3. **Upsert** — a single writer merges every source's contribution into one record
   per vulnerability, keyed by a stable `LVDB-XXXXXXXX` identifier.
4. **Serve** — Hasura exposes the schema as GraphQL with a read-only role.

## Where to go next

- **[Pipeline overview](ingest/index.md)** — how sync, transform, and upsert fit together.
- **[LVE schema](ingest/schema.md)** — the unified record every source maps onto.
- **[Data sources](datasources/index.md)** — per-source feeds, field mappings, and schema coverage.
- **[GraphQL examples](graphql-example-queries.md)** — ready-to-run queries.
- **[Documentation conventions](datasource_blueprint.md)** — how to document a new source.

For installation and the full CLI reference, see [Running limoza-vDB](running/docker.md).

> **License:** limoza-vDB is source-available under
> [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0) —
> free for noncommercial use, modification, and distribution.
