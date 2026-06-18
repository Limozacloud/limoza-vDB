# Docker stack

limoza-vDB ships as a Docker Compose stack. Everything — the database, the ingest CLI,
and the GraphQL API — runs in containers, so the only host requirements are **Docker**
and **Docker Compose**.

## Services

`docker-compose.yml` defines five services:

| Service | Image | Role | Exposed |
|---------|-------|------|---------|
| `postgres` | `postgres:16-alpine` | The database — stores the normalized LVE records | `127.0.0.1:5432` |
| `ingest` | built from `Dockerfile` | The Python sync/import CLI (one-shot, see below) | — |
| `hasura` | GraphQL Engine | Serves the schema as a read-only GraphQL API | `8080` |
| `pgadmin` | `dpage/pgadmin4` | Database UI (development convenience) | `5050` |
| `ofelia` | `mcuadros/ofelia` | Cron scheduler that runs the sync/import pipelines | — |

The `ingest` service is **not** a long-running daemon — it sits behind a Compose
[profile](https://docs.docker.com/compose/profiles/) (`profiles: [ingest]`) so it never
starts with `docker compose up`. You invoke it on demand with `docker compose run`
(see [Ingest CLI](cli.md)).

## Data persistence

Each source downloads into its own named volume mounted under `/data/<source>` inside
the `ingest` container (e.g. `/data/redhat`, `/data/nvd`, `/data/ghsa`). These volumes
survive container restarts, so a re-`sync` only fetches incremental changes rather than
re-downloading everything. The database lives in the `postgres_data` volume.

## First-run setup

```bash
# 1. Configure environment
cp .env.template .env
# Edit .env and set at least:
#   POSTGRES_PASSWORD     — database password
#   HASURA_ADMIN_SECRET   — admin secret for Hasura
#   NVD_API_KEY           — optional but strongly recommended (faster NVD/CPE sync)
# Generate a JWT signing key for read-only API tokens:
echo "HASURA_JWT_SECRET=$(openssl rand -hex 32)" >> .env

# 2. Start the long-running services
docker compose up -d postgres hasura

# 3. Apply the database schema (idempotent)
docker compose run --rm ingest schema

# 4. Download and import data (start small, or use `all`)
docker compose run --rm ingest sync redhat
docker compose run --rm ingest import redhat

# 5. Wire up the GraphQL API (once)
docker compose run --rm ingest hasura-init
```

After this, the GraphQL endpoint is at `http://localhost:8080/v1/graphql` and the
Hasura console at `http://localhost:8080/console`.

!!! note "Configuration via `.env`"
    All services read from `.env` (`env_file: .env`). Secrets — the database password,
    `HASURA_ADMIN_SECRET`, `HASURA_JWT_SECRET`, `NVD_API_KEY` — are **never** committed;
    only `.env.template` (with placeholders) is tracked. Rotate every secret before
    deploying.

## Production variant

`docker-compose.prod.yml` is a hardened variant: Postgres exposes no host port, the
Hasura console is disabled (`HASURA_GRAPHQL_ENABLE_CONSOLE=false`), and pgAdmin is
omitted. Use it with:

```bash
docker compose -f docker-compose.prod.yml up -d
```

## Scheduled runs

The `ofelia` service runs jobs on a cron schedule defined in `config/ofelia.ini`, which
invokes the `pipeline` command against jobs declared in `config/schedule.json`
(`daily`, `weekly`). See [Ingest CLI → pipeline](cli.md#pipeline).
