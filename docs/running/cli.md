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
| `records` | `cvelistv5`, `nvd` |
| `scoring` | `epss`, `kev`, `ssvc` |
| `advisories` | `redhat`, `suse`, `ubuntu`, `debian`, `oracle`, `almalinux`, `rocky`, `microsoft`, `ghsa`, `osv`, `nodejs` |
| `exploits` | `exploitdb`, `metasploit`, `nuclei`, `poc_github` |

## Command overview

| Command | What it does |
|---------|--------------|
| [`sync`](#sync) | Download / update one or more sources |
| [`ingest`](#ingest) | Write synced data into the database |
| [`affected`](#affected) | Derive the L4 affected-version layer (after sync + ingest) |
| [`match`](#match) | Version-compare a scanned component against the affected layer |
| [`daily`](#daily) | Full pipeline (schema → sync → ingest → affected → hasura-init) — the scheduler's job |
| [`api`](#api) | Serve the [REST API](rest-api.md) (bulk `/match` + `/lve`) |
| [`schema`](#schema) | Apply the database schema |
| [`hasura-init`](#hasura-init) | Track tables + relationships + role permissions |
| [`create-token`](#create-token) | Mint a GraphQL/API JWT (read-only, or write roles) |

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

## affected

Derives the [affected-version layer (L4)](../affected-versions.md) from the already
synced + ingested sources — one central pass after `sync` + `ingest`. Each extractor
owns its slice (delete-by-`origin`, reinsert). With no target it rebuilds everything;
pass source keys to rebuild only those.

```bash
docker compose exec ingest vdb affected                     # full rebuild
docker compose exec ingest vdb affected cvelistv5 microsoft  # only these origins
```

CPE-producing sources (`cvelistv5`, `microsoft`) validate every CPE against the NVD
catalogue; the distro/ecosystem sources produce purl rows.

## match

Version-compares a scanned component against `affected` and prints the vulnerable CVEs
(fixed version, status, source). Accepts a **purl** or a **CPE 2.3** string; the version
may be in the identifier or given as a second argument.

```bash
docker compose exec ingest vdb match pkg:rpm/redhat/openssl@1.0.1e-30.el6_6.1
docker compose exec ingest vdb match pkg:deb/ubuntu/curl 7.81.0-1 jammy
docker compose exec ingest vdb match 'cpe:2.3:o:microsoft:windows_server_2012:6.3.9600.20000:r2:*:*:*:*:*:*'
```

This is the same engine behind the MCP [`check_vulnerable`](mcp.md#tools) tool. See
[Affected versions → the matcher](../affected-versions.md#the-matcher).

## daily

The complete pipeline in order — **schema → sync → ingest → affected → hasura-init** —
as one command. This is exactly what the [scheduler](docker.md#scheduled-runs) runs
every night.

```bash
docker compose exec ingest vdb daily
```

Every phase runs regardless of per-source `sync`/`ingest` failures (those are isolated
and recorded in `sync_log`); a hard failure in schema / affected / hasura-init aborts.
It is a single subcommand on purpose — the scheduler invokes `vdb daily`, never a shell
pipeline (ofelia doesn't shell-parse its `command`, so `sh -c "a && b"` would break).

## api

Serves the [REST API](rest-api.md) — bulk `POST /match` and `POST /lve` for batch callers
(a scanner / pipeline), no LLM and no per-call token cost. This is the `command` of the
`api` compose service; run it directly to debug.

```bash
docker compose exec ingest vdb api      # listens on $API_PORT (default 8770)
```

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

Mints a JWT for the GraphQL/REST API (default TTL 1 day, role `readonly`).
Requires `HASURA_JWT_SECRET` in `.env`.

```bash
docker compose exec ingest vdb create-token                                    # 1-day read-only token
docker compose exec ingest vdb create-token --ttl 90                           # 90-day token
docker compose exec ingest vdb create-token --role lve_writer                  # read + create LVEs
docker compose exec ingest vdb create-token --role lve_writer,curation_writer  # both write roles
```

`--role` accepts one or several comma-separated roles → one token holding them all; `readonly`
is always included and the first role is the default. The write roles are `lve_writer` (create
LVEs) and `curation_writer` (create curations). Hasura and the REST `/lve` / `/curation`
endpoints enforce the role. See [GraphQL & Hasura → tokens](graphql.md#read-only-tokens).

## Running ad-hoc Python

To inspect downloaded source files, call Python directly inside the container:

```bash
docker compose exec ingest python3 -c "import glob; print(len(glob.glob('/data/redhat/**/*.json', recursive=True)))"
```
