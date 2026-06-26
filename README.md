# limoza-vDB

A CVE-centric vulnerability aggregation system. limoza-vDB syncs CVE and advisory data
from 20+ upstream sources, stores each source's contribution **side by side** in
PostgreSQL keyed by CVE id, and exposes everything through a read-only GraphQL API, a
REST match API, and an MCP server for LLM clients.

The **CVE id is the only join key** — there is no synthetic identifier and no single
merged record per vulnerability. A thin `cve` spine registers every CVE id; each source
writes into its own rows tagged with where the data came from; a CVE's full picture is
assembled at query time by joining on `cve_id`. Because no source owns the shared rows,
imports are order-independent and one source failing never blocks the others.

```
            sync                 transform              write
 source ─────────────▶ /data/<source> ─────▶ rows (per source) ─────▶ PostgreSQL ─────▶ Hasura GraphQL
 feeds                  (local volume)        (ingest/)                (schema.sql)      (read-only API)
```

## The layers

| Layer | What it answers | Where |
|-------|-----------------|-------|
| **Enrichment** | descriptions, CVSS, CWE, references, exploits, EPSS/KEV/SSVC | `cve_*` tables |
| **Advisory tiers (L1–L3)** | who assigned it (CNA), what the upstream advisory says, which downstream distros/ecosystems shipped a fix | `cve_levels()` |
| **Affected versions (L4)** | *which versions* are affected/fixed — so a scanned build can be version-compared | `affected` table |

The L4 layer is keyed by two coordinates: `purl` for managed/ecosystem software
(`pkg:rpm/redhat/openssl`, `pkg:deb/ubuntu/curl`) and `cpe` for unmanaged/binary/OS
software (Windows builds, vendor binaries). Every CPE is validated against the NVD CPE
dictionary so a stored row and a scanned component land on the same key.

## Components

- **PostgreSQL** — the store (`schema.sql`, declarative via pgschema).
- **Hasura** — read-only GraphQL over the schema.
- **`vdb` ingest CLI** (`ingest/`) — sync, ingest, affected derivation, matching.
- **REST API** (`ingest/api.py`) — `POST /match` (bulk scan) + `POST /lve`.
- **MCP server** (`mcp-server/`) — vulnerability data as MCP tools for any LLM client.

## Quickstart

```bash
# set POSTGRES_* / HASURA_* secrets in .env
docker compose up -d          # postgres + hasura + ingest + api + mcp
docker compose exec ingest vdb schema     # apply schema.sql

# pull + ingest sources, then derive the affected layer
docker compose exec ingest vdb daily      # sync + ingest + affected, end to end
```

Local development builds the images (`docker-compose.dev.yml`); production pulls the
published images (`docker-compose.prod.yml`, `ghcr.io/limozacloud/limoza-vdb*`).

## Using it

```bash
# match a scanned component against the affected layer
vdb match pkg:deb/debian/curl@7.74.0-1.3+deb11u16?distro=debian-11
vdb match 'cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*'

# mint a read-only token for the GraphQL / REST / MCP APIs
vdb create-token --ttl 90
```

- **GraphQL:** `http://<host>:8080/v1/graphql` (read-only role) — see
  [docs/graphql-example-queries.md](docs/graphql-example-queries.md).
- **REST `/match`:** bulk-scan a host's components (purl/cpe + version) → per-component
  `vulnerable`/`compliant` + CVEs.
- **MCP tools:** `get_cve_detail`, `check_vulnerable`, `match_bulk`, `explain_status`,
  `create_lve` — see [docs/running/mcp.md](docs/running/mcp.md).

## Documentation

Full docs (MkDocs site, also under `docs/`):

- [Pipeline overview](docs/ingest/index.md) · [Data model](docs/ingest/schema.md)
- [Data sources](docs/datasources/index.md) — per-source feeds, field mappings, schema coverage
- [Advisory tiers (L1–L3)](docs/advisory-tiers.md) · [Affected versions (L4)](docs/affected-versions.md)
- [Running: Docker](docs/running/docker.md) · [CLI](docs/running/cli.md) ·
  [GraphQL](docs/running/graphql.md) · [REST API](docs/running/rest-api.md) ·
  [MCP](docs/running/mcp.md)

## License

Source-available under
[PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0)
(noncommercial use). Aggregated source data keeps each upstream feed's terms — see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) and the
[data sources](docs/datasources/index.md) page.
