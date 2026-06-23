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
| `get_cve_detail(cve_id)` | All known data for one CVE — descriptions, CVSS, CWEs, references, solutions/workarounds, impacts, vendor assessments, advisories, exploits, EPSS/KEV/SSVC triage signals, a sample of affected packages, and the L1–L3 advisory tiers. |
| `check_vulnerable(purl, version, release)` | Version-compares an installed package against the affected-version data: "is X version Y vulnerable?" Returns the matching CVEs with fixed version, status, and source. `release` (el9, jammy, bookworm, …) is required for OS packages, omitted for language ecosystems. |

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

The server is reachable over HTTPS at `https://<host>/mcp` and gated by a read-only
bearer token (mint one with [`create-token`](graphql.md#read-only-tokens)). Each
client keeps its **own** config — a server added in Claude Desktop is not visible in
the claude.ai web app, and vice versa. Replace `<host>` and `<your-readonly-token>`.

### Claude Code

Native HTTP transport — add to the `mcpServers` block of `~/.claude.json` (user) or
`.mcp.json` (project):

```json
{
  "mcpServers": {
    "limoza": {
      "type": "http",
      "url": "https://<host>/mcp",
      "headers": {
        "Authorization": "Bearer <your-readonly-token>"
      }
    }
  }
}
```

or via the CLI:

```bash
claude mcp add --transport http limoza https://<host>/mcp \
  --header "Authorization: Bearer <your-readonly-token>"
```

### Claude Desktop

Desktop's connector UI expects OAuth, so a static bearer token is passed through the
`mcp-remote` stdio bridge. Put the token in an `env` var and reference it from the
header — keeping the `Bearer …` value out of `args` (where the space gets
mis-parsed):

```json
{
  "mcpServers": {
    "limoza": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "https://<host>/mcp",
        "--header", "Authorization:${AUTH}"
      ],
      "env": {
        "AUTH": "Bearer <your-readonly-token>"
      }
    }
  }
}
```

Add it to `claude_desktop_config.json`, then fully restart Claude Desktop (quit via
the tray, not just close the window).

### claude.ai (web)

Settings → Connectors → Custom Connector → URL `https://<host>/mcp`. The web UI uses
OAuth; this server is bearer-only, so prefer Claude Code / Claude Desktop unless an
OAuth layer is added. (Custom connectors require a paid plan.)

### Other clients

Point any MCP-capable client or agent runtime (Gemini / Vertex AI / OpenAI) at the
same endpoint — the protocol is model-agnostic.

Then ask, for example: *"Use limoza to give me the CVE details for CVE-2026-49014"*
or *"Use limoza: is openssl 1.0.1e-30.el6_6.1 on RHEL 6 vulnerable?"*

## Image & releases

The release workflow builds and publishes the image to
`ghcr.io/limozacloud/limoza-vdb-mcp` (tags `<version>` and `latest`) alongside the main
ingest image. The production Compose service references it as
`image: ghcr.io/limozacloud/limoza-vdb-mcp:latest`.
