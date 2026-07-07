# limoza-vDB MCP server

A **real MCP server** (it exposes tools; it never calls an LLM) that serves the
limoza-vDB vulnerability data over the [Model Context Protocol](https://modelcontextprotocol.io/).
Any MCP-capable client — the Claude chat window, Claude Desktop, Claude Code, or an
agent driving Gemini / Vertex AI / OpenAI — connects to it and the model decides when
to call the tools. The client holds the LLM key; this server does not.

It is **fully decoupled** from the ingest pipeline: it imports nothing from `ingest/`
and reaches the rest of the stack only through the read-only Hasura GraphQL API.

> The modules live flat in this folder on purpose — it is **not** a Python package
> (the import name `mcp` belongs to the SDK), so the entry point is `python server.py`.

## Tools

| Tool | Description |
|------|-------------|
| `get_cve_detail(cve_id)` | All known data for one CVE — descriptions, CVSS, CWEs, references, vendor assessments, advisories, exploits, EPSS/KEV/SSVC, a per-source affected summary, and the L1–L3 advisory tiers. Compact, fixed-format output. |
| `check_vulnerable(purl, version, release)` | Version-compare a scanned component against the affected-version data ("is X version Y vulnerable?"). Accepts a purl or a CPE 2.3 string. |
| `match_bulk(components)` | `check_vulnerable` for a whole scan in one call — per-component `vulnerable`/`compliant` + CVEs + summary counts. |
| `explain_status(cve_id, package, release)` | Explain **why** a CVE/package has its status, with the vendor source + a verify link (per-CVE or per-package mode). |

The server is **read-only** — every tool queries, none mutates. Writes (LVEs, curations) go
through the REST API (or the equivalent GraphQL mutations).

See [docs/running/mcp.md](../docs/running/mcp.md) for the full reference.

## Transport & auth

- **Streamable HTTP**, endpoint `…/mcp` (default port `8765`), so it works remotely.
- **Bearer token** via `MCP_AUTH_TOKEN` (`Authorization: Bearer <token>`).
- Talks to Hasura with a **read-only** token: either `GRAPHQL_TOKEN` (verbatim, the same
  token the GraphQL API uses) or a JWT minted from the shared `HASURA_JWT_SECRET`
  (role `readonly`, identical to the `create-token` CLI).

## Run

It ships as a service in both `docker-compose.dev.yml` (built locally) and
`docker-compose.prod.yml` (pre-built image `ghcr.io/limozacloud/limoza-vdb-mcp`). Set
`MCP_AUTH_TOKEN` in `.env`, then:

```bash
docker compose up -d mcp
```

Standalone (without Compose):

```bash
pip install -r requirements.txt
export MCP_AUTH_TOKEN=$(openssl rand -hex 32)
export GRAPHQL_URL=http://localhost:8080/v1/graphql
export HASURA_JWT_SECRET=...        # or GRAPHQL_TOKEN=...
python server.py
```

## Connect it to Claude

The server must be reachable over HTTPS from the internet for the **claude.ai** chat
window (a reverse proxy terminates TLS in front of port 8765).

- **claude.ai:** Settings → Connectors → Custom Connector → URL `https://<host>/mcp`,
  with the bearer token. (Custom connectors require a paid plan.)
- **Claude Code:** `claude mcp add --transport http limoza https://<host>/mcp --header "Authorization: Bearer <token>"`
- **Claude Desktop:** add it as a remote connector.

Then ask, e.g., *"Use limoza to give me the CVE details for CVE-2026-49014."*
