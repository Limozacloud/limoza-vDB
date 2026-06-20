# Ingest CLI

All operations run through the `ingest` container, which runs continuously as an idle
service. Use `docker compose exec ingest /entrypoint.sh …` to run commands inside it:

```bash
docker compose exec ingest /entrypoint.sh <command> [args]
```

Running the container with no command (`docker compose up -d ingest`) keeps it idle — it does not print help.

## Command overview

| Command | What it does |
|---------|--------------|
| [`sync`](#sync) | Download / update one or more sources |
| [`import`](#import) | Normalize synced data into the database |
| [`pipeline`](#pipeline) | Run `sync` + `import` for a named job |
| [`schema`](#schema) | Apply the database schema |
| [`hasura-init`](#hasura-init) | Track tables + relationships + read-only permissions |
| [`create-token`](#create-token) | Mint a read-only GraphQL JWT |
| [`truncate`](#truncate) | Empty data tables |
| [`verify`](#verify) | Compare a CVE against upstream OSV |

## sync

Downloads raw source data into the local `/data/<source>` volumes. Must run before
`import`. Each source has its own target; `sync all` fetches everything.

```bash
docker compose exec ingest /entrypoint.sh sync redhat
docker compose exec ingest /entrypoint.sh sync nvd epss cisa_kev      # several at once
docker compose exec ingest /entrypoint.sh sync all
```

Sources support incremental sync where the upstream allows it (checkpoints / change
feeds), so repeated runs only fetch what changed. The full target list is on the
[Data Sources](../datasources/index.md) pages.

## import

Reads the synced data and writes it into the unified **LVE record** (tables `lve`,
`lve_cve`, `lve_titles`, `lve_packages`, …). Before each source runs, the CLI checks
that the matching `sync` has been done and skips with a hint if not.

```bash
docker compose exec ingest /entrypoint.sh import redhat
docker compose exec ingest /entrypoint.sh import nvd redhat suse ubuntu
docker compose exec ingest /entrypoint.sh import all
```

Import order does **not** matter — the schema is order-independent, and only NVD writes
the `cve` spine fields; every other source merges with `COALESCE`, so no source
overwrites another's non-null data.

**Single-CVE mode** — restrict a run to one vulnerability with `--cve`, handy for
testing a mapping:

```bash
docker compose exec ingest /entrypoint.sh import nvd redhat suse --cve CVE-2024-3094
```

## pipeline

Runs a `sync` followed by an `import` for a job defined in `config/schedule.json`.

```bash
docker compose exec ingest /entrypoint.sh pipeline daily
```

The `ofelia` service runs this automatically at 02:30 every night (`config/ofelia.ini`).

## schema

Applies `schema.sql` via `pgschema`. Idempotent — safe to run repeatedly. `import`
applies the schema automatically, so you only need this to apply schema changes without
importing data.

```bash
docker compose exec ingest /entrypoint.sh schema
```

## hasura-init

Run once after the first `import`. It tracks all tables in Hasura, builds the object/
array relationships between `lve` and its child tables, and grants the `readonly` role
SELECT access. See [GraphQL & Hasura](graphql.md).

```bash
docker compose exec ingest /entrypoint.sh hasura-init
```

## create-token

Mints a read-only JWT for the GraphQL API (default TTL 1 day). Requires
`HASURA_JWT_SECRET` in `.env`.

```bash
docker compose exec ingest /entrypoint.sh create-token            # 1-day token
docker compose exec ingest /entrypoint.sh create-token --ttl 90   # 90-day token
```

See [GraphQL & Hasura → tokens](graphql.md#read-only-tokens).

## truncate

Empties data tables. Truncating **all** tables requires `--yes`; naming specific tables
does not.

```bash
docker compose exec ingest /entrypoint.sh truncate lve_packages    # one table
docker compose exec ingest /entrypoint.sh truncate --yes           # everything
```

## verify

Fetches a CVE from upstream OSV and compares it against what the database holds — a
quick sanity check for coverage gaps.

```bash
docker compose exec ingest /entrypoint.sh verify CVE-2024-3094
```

## Running ad-hoc Python

The container's entrypoint intercepts commands, so to run a raw Python one-liner (for
inspecting downloaded source files) use `docker compose exec` with the `-it` flag and
call Python directly:

```bash
docker compose exec ingest python3 -c "import json, glob; print(len(glob.glob('/data/redhat/**/*.json', recursive=True)))"
```
