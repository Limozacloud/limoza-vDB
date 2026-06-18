"""The MCP server itself: a real MCP server (it exposes tools and never calls an LLM).

Transport is Streamable HTTP so it can be reached remotely — e.g. added as a custom
connector in the Claude chat window, or by any other MCP-capable client driving its
own LLM (Gemini, Vertex AI, OpenAI, Claude).

Run it directly: ``python server.py`` (this folder is intentionally NOT a Python
package — the import name ``mcp`` belongs to the SDK).
"""

import logging
import secrets

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from config import load_settings
from hasura import HasuraClient
from queries import FULL_CVE_SCAN

log = logging.getLogger("limoza-mcp")

settings = load_settings()
hasura = HasuraClient(settings)

mcp = FastMCP("limoza-vdb", stateless_http=True, host=settings.host, port=settings.port)


@mcp.tool()
async def get_cve_detail(cve_id: str) -> dict:
    """Return all known data for a single CVE from limoza-vDB.

    Use this to look up a vulnerability by its CVE identifier (e.g. "CVE-2026-49014").
    Returns titles, descriptions, CVSS scores, CWE weaknesses, references, vendor
    advisories, upstream fix info, affected/fixed packages across all distros,
    mitigations, impacts, known exploits, EPSS/KEV/SSVC triage signals, and the
    change history. Returns {"found": false} when no record exists for the CVE.

    Args:
        cve_id: A CVE identifier such as "CVE-2026-49014" (case-insensitive).
    """
    cve_id = cve_id.strip().upper()
    data = await hasura.query(FULL_CVE_SCAN, {"cve_id": cve_id})
    rows = data.get("lve_cve") or []
    if not rows:
        return {
            "found": False,
            "cve_id": cve_id,
            "message": "No record found for this CVE in limoza-vDB.",
        }
    return {"found": True, "cve_id": cve_id, "record": rows[0]}


class BearerAuthMiddleware:
    """Pure-ASGI bearer-token gate (kept ASGI-level so it never buffers MCP streams)."""

    def __init__(self, app, token: str | None) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.token is None:
            await self.app(scope, receive, send)
            return
        if scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode()
        if not (auth and secrets.compare_digest(auth, f"Bearer {self.token}")):
            await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
            return
        await self.app(scope, receive, send)


async def _health(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def build_app():
    app = mcp.streamable_http_app()
    app.routes.append(Route("/healthz", _health, methods=["GET"]))
    app.add_middleware(BearerAuthMiddleware, token=settings.auth_token)
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if settings.auth_token is None:
        log.warning(
            "MCP_AUTH_TOKEN is not set — the MCP endpoint is UNAUTHENTICATED. "
            "Set MCP_AUTH_TOKEN before exposing this server."
        )
    log.info("limoza-vDB MCP server on http://%s:%s/mcp (GraphQL: %s)",
             settings.host, settings.port, settings.graphql_url)
    uvicorn.run(build_app(), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
