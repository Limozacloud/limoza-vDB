# MCP server

limoza-vDB ships an **optional** [Model Context Protocol](https://modelcontextprotocol.io/)
server that exposes the vulnerability data as MCP **tools**. Any MCP-capable client —
the Claude chat window, Claude Desktop, Claude Code, or an agent driving Gemini,
Vertex AI or OpenAI — connects to it, and the model decides when to call the tools.

```
 MCP client / host                         MCP server (this)        rest of the stack
 ┌───────────────────┐      MCP over      ┌──────────────────┐     ┌─────────────────┐
 │ holds the LLM key │   Streamable HTTP  │ exposes tools,   │     │ Hasura GraphQL  │
 │ runs the convo    │◀──────────────────▶│ never calls an   │────▶│ (read-only API) │
 │ (Claude / Gemini  │   Bearer token     │ LLM itself       │     │                 │
 │  / Vertex / OpenAI)│                   └──────────────────┘     └─────────────────┘
 └───────────────────┘
```

!!! note "Server, not host"
    An MCP **server** holds no LLM key and never calls a model — the LLM lives in the
    **client/host**. Each customer brings their own model; the server only answers
    "here are my tools" and "here is the result of tool *X*". This is what makes it
    work with any provider.

It is **fully decoupled** from the ingest pipeline: the code lives in `mcp-server/`,
imports nothing from `ingest/`, and reaches the rest of the stack only through the
read-only [GraphQL API](graphql.md).

## Tools

| Tool | Description |
|------|-------------|
| `get_cve_detail(cve_id)` | All known data for one CVE — titles, descriptions, CVSS, CWEs, references, vendor advisories, upstream fixes, affected/fixed packages across all distros, mitigations, impacts, exploits, EPSS/KEV/SSVC triage signals, and history. |

More tools (mitigations per distro, package status, triage) are planned; this first
release ships a single use case.

## Enable it

The server is defined as a **commented-out** `mcp` service in `docker-compose.prod.yml`.
Uncomment that block, set a bearer token in `.env`, then start it:

```bash
# 1. Add a bearer token to .env
echo "MCP_AUTH_TOKEN=$(openssl rand -hex 32)" >> .env

# 2. Uncomment the `mcp:` service in docker-compose.prod.yml, then:
docker compose -f docker-compose.prod.yml up -d mcp
```

The MCP endpoint is then served at `http://<host>:8765/mcp` and a plain health check
at `/healthz`.

## Configuration

All settings come from the environment (the Compose service reads them from `.env`).

| Variable | Default | Purpose |
|----------|---------|---------|
| `MCP_AUTH_TOKEN` | *(none)* | Bearer token clients must present. **Unset = no auth** (logged as a warning; set it in production). |
| `MCP_PORT` | `8765` | Listen port inside the container. |
| `GRAPHQL_URL` | `http://hasura:8080/v1/graphql` | Hasura endpoint (the in-network service name under Compose). |
| `GRAPHQL_TOKEN` | *(none)* | A pre-minted read-only token to use verbatim — the same kind the GraphQL API uses. |
| `HASURA_JWT_SECRET` | *(shared)* | If `GRAPHQL_TOKEN` is unset, the server mints a short-lived read-only JWT from this shared key. |
| `GRAPHQL_TOKEN_TTL_DAYS` | `1` | TTL for a minted token. |

## Authentication

Two independent layers:

- **Client → MCP server:** a bearer token (`MCP_AUTH_TOKEN`), sent as
  `Authorization: Bearer <token>`. `/healthz` is exempt.
- **MCP server → Hasura:** a **read-only** token. Either `GRAPHQL_TOKEN` verbatim, or a
  JWT minted from the shared `HASURA_JWT_SECRET` with the `readonly` role — identical to
  the [`create-token`](graphql.md#read-only-tokens) CLI. The admin secret is never used.

## Connect a client

For the **claude.ai** chat window the server must be reachable over HTTPS from the
internet (terminate TLS with a reverse proxy in front of port 8765).

| Client | How |
|--------|-----|
| claude.ai | Settings → Connectors → Custom Connector → URL `https://<host>/mcp` + bearer token. (Custom connectors require a paid plan.) |
| Claude Code | `claude mcp add --transport http limoza https://<host>/mcp --header "Authorization: Bearer <token>"` |
| Claude Desktop | Add it as a remote connector. |
| Other (Gemini / Vertex AI / OpenAI) | Point any MCP-capable client or agent runtime at the same endpoint — the protocol is model-agnostic. |

Then ask, for example: *"Use limoza to give me the CVE details for CVE-2026-49014."*

## Image & releases

The release workflow builds and publishes the image to
`ghcr.io/limozacloud/limoza-vdb-mcp` (tags `<version>` and `latest`) alongside the main
ingest image. The production Compose service references it as
`image: ghcr.io/limozacloud/limoza-vdb-mcp:latest`.
