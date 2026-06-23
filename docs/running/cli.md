# Ingest CLI

All operations run through the `ingest` container, which runs continuously as an idle
service. The CLI is `vdb` (a thin wrapper for `python -m ingest.run`):

```bash
docker compose exec ingest vdb <command> [targets…]
```

Running the container with no command keeps it idle (`sleep infinity`) so
`docker compose exec` and the scheduler can run commands inside it.

## Targets

`sync` and `ingest` take **targets** — a single source key or a group. With no
target they act on everything.

| Group | Members |
|-------|---------|
| `reference` | `cna`, `cpe`, `cwe`, `source_urls` |
| `records` | `cvelistv5` |
| `scoring` | `epss`, `kev`, `ssvc` |
| `advisories` | `redhat`, `suse`, `ubuntu`, `debian`, `oracle`, `almalinux`, `rocky`, `microsoft`, `ghsa`, `osv` |
| `exploits` | `exploitdb`, `metasploit`, `nuclei`, `poc_github` |

## Command overview

| Command | What it does |
|---------|--------------|
| [`sync`](#sync) | Download / update one or more sources |
| [`ingest`](#ingest) | Write synced data into the database |
| [`schema`](#schema) | Apply the database schema |
| [`hasura-init`](#hasura-init) | Track tables + relationships + read-only permissions |
| [`create-token`](#create-token) | Mint a read-only GraphQL JWT |

## sync

Downloads raw source data into the local `/data/<source>` volumes. Must run before
`ingest`. Sources sync incrementally where the upstream allows it (checkpoints /
change feeds), so repeated runs only fetch what changed.

```bash
docker compose exec ingest vdb sync redhat
docker compose exec ingest vdb sync cvelistv5 epss kev      # several at once
docker compose exec ingest vdb sync advisories              # a whole group
docker compose exec ingest vdb sync                         # everything
```

A source that is unchanged since the last run reports `no_new_data` and does
nothing.

## ingest

Reads the synced data and writes it into the database. Import order does **not**
matter — every source writes its own rows and the `cve` spine is shared
(`ON CONFLICT DO NOTHING`).

```bash
docker compose exec ingest vdb ingest redhat
docker compose exec ingest vdb ingest cvelistv5 redhat suse
docker compose exec ingest vdb ingest                       # everything synced
```

Each run is isolated and logged: a `sync_log` row records `success` / `no_new_data`
/ `failed` with the row delta. One source failing never aborts the rest.

## schema

Applies `schema.sql`. Idempotent — safe to run repeatedly; run it to apply schema
changes.

```bash
docker compose exec ingest vdb schema
```

## hasura-init

Run once after the first `ingest`. It tracks all tables in Hasura, wires the
CVE-spine relationships (manual, since there are no foreign keys), tracks the
`cve_levels` function, and grants the `readonly` role SELECT access. See
[GraphQL & Hasura](graphql.md).

```bash
docker compose exec ingest vdb hasura-init
```

## create-token

Mints a read-only JWT for the GraphQL API (default TTL 1 day, role `readonly`).
Requires `HASURA_JWT_SECRET` in `.env`.

```bash
docker compose exec ingest vdb create-token            # 1-day token
docker compose exec ingest vdb create-token --ttl 90   # 90-day token
```

See [GraphQL & Hasura → tokens](graphql.md#read-only-tokens).

## Running ad-hoc Python

To inspect downloaded source files, call Python directly inside the container:

```bash
docker compose exec ingest python3 -c "import glob; print(len(glob.glob('/data/redhat/**/*.json', recursive=True)))"
```
