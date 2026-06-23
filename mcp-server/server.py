"""The MCP server itself: a real MCP server (it exposes tools and never calls an LLM).

Transport is Streamable HTTP so it can be reached remotely — e.g. added as a custom
connector in the Claude chat window, or by any other MCP-capable client driving its
own LLM (Gemini, Vertex AI, OpenAI, Claude).

Run it directly: ``python server.py`` (this folder is intentionally NOT a Python
package — the import name ``mcp`` belongs to the SDK).
"""

import logging

import jwt as pyjwt
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
    """Return all known data for a single CVE from the limoza-vDB vulnerability database.

    IMPORTANT: Base your answer EXCLUSIVELY on the data returned by this tool.
    Do NOT supplement with your own training knowledge about this CVE.
    If a field is empty or missing in the result, state that explicitly — do not fill gaps from memory.

    Returns the CVE record (assigner/state/dates), descriptions, CVSS scores, CWE
    weaknesses, references, solutions/workarounds, impacts, aliases, per-vendor
    assessments, advisories, known exploits, EPSS/KEV/SSVC triage signals, a capped
    sample of affected packages, and the tiered advisory view (advisory_tiers:
    L1 CNA / L2 upstream / L3 downstream). Returns {"found": false} when no record
    exists for the CVE.

    Args:
        cve_id: A CVE identifier such as "CVE-2024-3094" (case-insensitive).
    """
    cve_id = cve_id.strip().upper()
    data = await hasura.query(FULL_CVE_SCAN, {"cve_id": cve_id})
    rec = data.get("cve_by_pk")
    if not rec:
        return {
            "found": False,
            "cve_id": cve_id,
            "message": "No record found for this CVE in limoza-vDB.",
        }
    return {
        "found": True,
        "cve_id": cve_id,
        "record": rec,
        "advisory_tiers": data.get("cve_levels") or [],
    }


class BearerAuthMiddleware:
    """Pure-ASGI JWT gate — accepts tokens minted by `ingest create-token`."""

    def __init__(self, app, jwt_secret: str | None) -> None:
        self.app = app
        self.jwt_secret = jwt_secret

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.jwt_secret is None:
            await self.app(scope, receive, send)
            return
        if scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode()
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        try:
            pyjwt.decode(token, self.jwt_secret, algorithms=["HS256"])
        except pyjwt.PyJWTError:
            await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
            return
        await self.app(scope, receive, send)


async def _health(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def build_app():
    app = mcp.streamable_http_app()
    app.routes.append(Route("/healthz", _health, methods=["GET"]))
    app.add_middleware(BearerAuthMiddleware, jwt_secret=settings.jwt_secret)
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if settings.jwt_secret is None:
        log.warning(
            "HASURA_JWT_SECRET is not set — the MCP endpoint is UNAUTHENTICATED."
        )
    log.info("limoza-vDB MCP server on http://%s:%s/mcp (GraphQL: %s)",
             settings.host, settings.port, settings.graphql_url)
    uvicorn.run(build_app(), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
