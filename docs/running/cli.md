# Ingest CLI

All operations run through the `ingest` container. Because it sits behind a Compose
profile, you invoke it one command at a time with `docker compose run --rm ingest …`
(`--rm` removes the throwaway container afterwards):

```bash
docker compose run --rm ingest <command> [args]
```

Running `ingest` with no command prints the built-in help.

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
docker compose run --rm ingest sync redhat
docker compose run --rm ingest sync nvd epss cisa_kev      # several at once
docker compose run --rm ingest sync all
```

Sources support incremental sync where the upstream allows it (checkpoints / change
feeds), so repeated runs only fetch what changed. The full target list is on the
[Data Sources](../datasources/index.md) pages.

## import

Reads the synced data and writes it into the unified **LVE record** (tables `lve`,
`lve_cve`, `lve_titles`, `lve_packages`, …). Before each source runs, the CLI checks
that the matching `sync` has been done and skips with a hint if not.

```bash
docker compose run --rm ingest import redhat
docker compose run --rm ingest import nvd redhat suse ubuntu
docker compose run --rm ingest import all
```

Import order does **not** matter — the schema is order-independent, and only NVD writes
the `cve` spine fields; every other source merges with `COALESCE`, so no source
overwrites another's non-null data.

**Single-CVE mode** — restrict a run to one vulnerability with `--cve`, handy for
testing a mapping:

```bash
docker compose run --rm ingest import nvd redhat suse --cve CVE-2024-3094
```

## pipeline

Runs a `sync` followed by an `import` for a job defined in `config/schedule.json`.
Two jobs ship by default:

| Job | Contents |
|-----|----------|
| `daily` | NVD, the distro sources, Microsoft, and the scoring sources (EPSS/KEV/SSVC/BSI/Nuclei) |
| `weekly` | The heavier exploit-intel / ecosystem sources (Exploit-DB, Metasploit, PoC-in-GitHub, GHSA, OSV) |

```bash
docker compose run --rm ingest pipeline daily
docker compose run --rm ingest pipeline weekly
```

The `ofelia` service runs these automatically on a cron schedule (`config/ofelia.ini`).

## schema

Applies `schema.sql` via `pgschema`. Idempotent — safe to run repeatedly. `import`
applies the schema automatically, so you only need this to apply schema changes without
importing data.

```bash
docker compose run --rm ingest schema
```

## hasura-init

Run once after the first `import`. It tracks all tables in Hasura, builds the object/
array relationships between `lve` and its child tables, and grants the `readonly` role
SELECT access. See [GraphQL & Hasura](graphql.md).

```bash
docker compose run --rm ingest hasura-init
```

## create-token

Mints a read-only JWT for the GraphQL API (default TTL 1 day). Requires
`HASURA_JWT_SECRET` in `.env`.

```bash
docker compose run --rm ingest create-token            # 1-day token
docker compose run --rm ingest create-token --ttl 90   # 90-day token
```

See [GraphQL & Hasura → tokens](graphql.md#read-only-tokens).

## truncate

Empties data tables. Truncating **all** tables requires `--yes`; naming specific tables
does not.

```bash
docker compose run --rm ingest truncate lve_packages    # one table
docker compose run --rm ingest truncate --yes           # everything
```

## verify

Fetches a CVE from upstream OSV and compares it against what the database holds — a
quick sanity check for coverage gaps.

```bash
docker compose run --rm ingest verify CVE-2024-3094
```

## Running ad-hoc Python

The container's entrypoint intercepts commands, so to run a raw Python one-liner (for
inspecting downloaded source files) override the entrypoint:

```bash
docker compose run --rm --entrypoint python3 ingest -c "import json, glob; print(len(glob.glob('/data/redhat/**/*.json', recursive=True)))"
```
