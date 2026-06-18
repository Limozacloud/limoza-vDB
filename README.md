# limoza-vDB

A multi-vendor vulnerability aggregation system. limoza-vDB syncs CVE and advisory
data from 20+ upstream sources, normalizes everything into a single unified schema
(the **LVE record**), stores it in PostgreSQL, and exposes it through a read-only
GraphQL API.

> **License note:** This project is **source-available**, not OSI "open source".
> It is licensed under [PolyForm Noncommercial 1.0.0](LICENSE.md): you may freely
> use, modify, and share it for any **noncommercial** purpose, but commercial use
> is not permitted. See [License](#license).

---

## What it does

- **Sync** — downloads raw data from each vendor (CSAF, OVAL, OSV, CVRF, JSON feeds, git repos) into local volumes, incrementally where the source supports it.
- **Transform** — each vendor module maps its source format onto the common LVE schema.
- **Upsert** — a single writer (`ingest/db.py`) merges every vendor's contribution into one record per vulnerability, keyed by a stable `LVDB-XXXXXXXX` identifier.
- **Serve** — Hasura exposes the PostgreSQL schema as GraphQL with a read-only role and JWT tokens.

Each vulnerability becomes one **LVE record** aggregating titles, descriptions, CVSS,
CWEs, references, advisories, affected/fixed packages, exploit intelligence, and a
change history — with every field tagged by its `source` vendor.

## Data sources

| Category | Sources |
|----------|---------|
| **Linux distributions** | Red Hat, SUSE, Ubuntu, Debian, Alpine, AlmaLinux, Rocky Linux, Oracle Linux |
| **OS / vendor** | Microsoft MSRC |
| **CVE baseline** | NVD / MITRE |
| **Package ecosystems** | GitHub Security Advisories (GHSA), OSV |
| **Risk scoring** | FIRST EPSS, CISA KEV, CISA SSVC, BSI WID |
| **Exploit intelligence** | Exploit-DB, Metasploit, Nuclei, PoC-in-GitHub |
| **Dictionaries** | NVD CPE, CWE |

Per-source field mappings and schema-coverage details live in
[`docs/datasources/`](docs/datasources/). Red Hat is the reference implementation.

## Architecture

```
            sync                transform              upsert
 vendor ─────────────▶ /data/<vendor> ─────▶ LVE record ─────▶ PostgreSQL ─────▶ Hasura GraphQL
 feeds                  (local volume)        (ingest/)         (schema.sql)      (read-only API)
```

The Docker Compose stack runs:

| Service | Purpose |
|---------|---------|
| `postgres` | PostgreSQL 16 — the database |
| `ingest` | The Python sync/import CLI (built from `Dockerfile`) |
| `hasura` | GraphQL Engine over the schema |
| `pgadmin` | Database UI (development only) |
| `ofelia` | Cron scheduler for the sync/import pipelines |

## Quickstart

Requires Docker and Docker Compose. The repo ships `docker-compose.dev.yml` (local)
and `docker-compose.prod.yml` (hardened); copy one to the git-ignored default name so
you can customize it freely.

```bash
# 1. Pick a compose file + configure environment
cp docker-compose.dev.yml docker-compose.yml   # or pass -f docker-compose.dev.yml
cp .env.template .env
# Edit .env: set POSTGRES_PASSWORD, HASURA_ADMIN_SECRET, and (recommended) NVD_API_KEY.
# Generate a JWT signing key for read-only tokens:
echo "HASURA_JWT_SECRET=$(openssl rand -hex 32)" >> .env

# 2. Start the stack
docker compose up -d postgres hasura

# 3. Apply the database schema
docker compose run --rm ingest schema

# 4. Sync and import data (example: a single source)
docker compose run --rm ingest sync redhat
docker compose run --rm ingest import redhat

# 5. Wire up the GraphQL API (once)
docker compose run --rm ingest hasura-init
```

The GraphQL endpoint is then at `http://localhost:8080/v1/graphql` and the Hasura
console at `http://localhost:8080/console`.

For the full command reference, see the **Running limoza-vDB** section of the docs
([Ingest CLI](docs/running/cli.md), [Docker stack](docs/running/docker.md),
[GraphQL & Hasura](docs/running/graphql.md)).

## CLI

The `ingest` container is the entrypoint for all operations:

| Command | Description |
|---------|-------------|
| `sync <target...>` | Download / update one or more sources (or `all`) |
| `import <vendor...>` | Import synced data into the database (or `all`) |
| `pipeline <job>` | Run sync + import for a job defined in `config/schedule.json` |
| `schema` | Apply the database schema (idempotent) |
| `hasura-init` | Track tables, build relationships, grant the read-only role |
| `create-token [--ttl DAYS]` | Mint a read-only JWT for the GraphQL API |
| `truncate [--yes] [table...]` | Truncate data tables |
| `verify <CVE-ID>` | Compare a CVE against upstream OSV |

## GraphQL API

Hasura serves the schema directly. The `readonly` role has SELECT-only access to all
tables. Mint a token with:

```bash
docker compose run --rm ingest create-token --ttl 90
```

and pass it as `Authorization: Bearer <token>`. Example queries are in
[`docs/graphql-example-queries.md`](docs/graphql-example-queries.md).

The stack uses a [custom Hasura build](docs/running/graphql.md#custom-hasura-build) — a
fork of Hasura CE (Apache-2.0) that adds `_any` / `_all` filter operators for
element-level matching on string-array columns such as `lve.aliases`.

## Documentation

Documentation is built with MkDocs:

```bash
pip install mkdocs
mkdocs serve   # http://127.0.0.1:8000
```

- [`docs/datasources/`](docs/datasources/) — per-source field mappings and schema coverage
- [`docs/ingest/schema.md`](docs/ingest/schema.md) — the LVE schema reference
- [`docs/running/`](docs/running/cli.md) — Docker stack, ingest CLI, and GraphQL/Hasura usage

## Security

Never commit real secrets. `.env` is git-ignored; only `.env.template` (with
placeholders) is tracked. All credentials — database password, Hasura admin secret,
JWT signing key, NVD API key — are read from the environment. If you fork this from
an internal deployment, **rotate every secret** before publishing.

## License

[PolyForm Noncommercial 1.0.0](LICENSE.md) — free for noncommercial use, modification,
and distribution. Commercial use is not granted by this license; contact the authors
for commercial terms.

Third-party software dependencies and runtime images are acknowledged in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Ingested **data** carries its own upstream licenses — several require attribution
(GHSA, OSV, EPSS, …). See
[Source data licenses](docs/datasources/index.md#source-data-licenses) and review each
source's terms before redistributing its data.
