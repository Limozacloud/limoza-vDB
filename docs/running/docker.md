# Docker stack

limoza-vDB ships as a Docker Compose stack. Everything — the database, the ingest
CLI, and the GraphQL API — runs in containers, so the only host requirements are
**Docker** and **Docker Compose**.

The repository ships two reference compose files: **`docker-compose.dev.yml`** (local
development — exposed ports, pgAdmin, the scheduler) and **`docker-compose.prod.yml`**
(hardened — TLS via Traefik, no exposed database, console disabled). Copy one to the
default name and customize freely:

```bash
cp docker-compose.dev.yml docker-compose.yml   # then `docker compose …` just works
```

## Services

| Service | Role | Exposed (dev) |
|---------|------|---------------|
| `postgres` | The database | `127.0.0.1:5432` |
| `ingest` | The sync/ingest CLI (one idle container, see below) | — |
| `hasura` | Serves the schema as a read-only GraphQL API | `8080` |
| `ofelia` | Cron scheduler that runs the sync/ingest pipeline | — |
| `pgadmin` | Database UI (development convenience) | `5050` |
| `traefik` | Reverse proxy / TLS termination (production) | `80`/`443` |
| `mcp` | Optional [MCP server](mcp.md) for LLM clients | `8765` |

The `ingest` service runs continuously as an idle process (`sleep infinity`) so that
`docker compose exec` and the scheduler can run commands inside it without spawning
throwaway containers. It consumes no CPU and minimal RAM while idle.

## Data persistence

Each source downloads into a named volume mounted under `/data/<source>` inside the
`ingest` container (e.g. `/data/cvelistv5`, `/data/redhat`, `/data/ghsa`). These
volumes survive restarts, so a re-`sync` only fetches incremental changes. The
database lives in the `postgres_data` volume.

## First-run setup

```bash
# 1. Pick a compose file
cp docker-compose.dev.yml docker-compose.yml

# 2. Configure environment
cp .env.template .env
# Edit .env and set at least:
#   POSTGRES_PASSWORD     — database password
#   HASURA_ADMIN_SECRET   — admin secret for Hasura
#   NVD_API_KEY           — optional but recommended (faster CPE dictionary sync)
# Generate a JWT signing key for read-only API tokens:
echo "HASURA_JWT_SECRET=$(openssl rand -hex 32)" >> .env

# 3. Start the core stack
docker compose up -d postgres hasura ingest

# 4. Apply the database schema (idempotent)
docker compose exec ingest vdb schema

# 5. Download and write data (start small, or use a group / everything)
docker compose exec ingest vdb sync   cvelistv5
docker compose exec ingest vdb ingest cvelistv5

# 6. Wire up the GraphQL API (once)
docker compose exec ingest vdb hasura-init
```

After this, the GraphQL endpoint is at `http://localhost:8080/v1/graphql` and the
Hasura console at `http://localhost:8080/console`.

!!! note "Configuration via `.env`"
    All services read from `.env` (`env_file: .env`). Secrets — the database password,
    `HASURA_ADMIN_SECRET`, `HASURA_JWT_SECRET`, `NVD_API_KEY` — are **never** committed;
    only `.env.template` (with placeholders) is tracked. Rotate every secret before
    deploying.

## Production variant

`docker-compose.prod.yml` is hardened: Postgres exposes no host port, the Hasura
console is disabled (`HASURA_GRAPHQL_ENABLE_CONSOLE=false`), pgAdmin is omitted, and
Traefik terminates TLS in front of the API.

```bash
docker compose -f docker-compose.prod.yml up -d
```

## Scheduled runs

The `ofelia` service runs the CLI on a cron schedule, defined in `config/ofelia.ini`
and `config/schedule.json`, so each source is kept fresh by periodic `sync` + `ingest`
runs without manual intervention. See the [Ingest CLI](cli.md).
