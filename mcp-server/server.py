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
from hasura import HasuraClient, request_token
from lve import create_lve as _create_lve
from matcher import check as match_check
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


@mcp.tool()
async def check_vulnerable(purl: str, version: str, release: str = "") -> dict:
    """Check whether an installed package version is affected by known CVEs (version-compared
    against limoza-vDB's affected-version data). Use this for "is X version Y vulnerable?".

    Build the purl from the platform:
      - RHEL / AlmaLinux / Rocky / Oracle rpm:  pkg:rpm/redhat/<name>  (release = el8, el9, el9_2…)
      - SUSE rpm:                               pkg:rpm/suse/<name>    (release = sles15sp7, leap15.6…)
      - Ubuntu / Debian deb:                    pkg:deb/ubuntu/<name>  (release = jammy, noble, bookworm…)
      - Language ecosystems:                    pkg:pypi/<name> · pkg:npm/<name> · pkg:golang/<mod>
                                                · pkg:cargo/<name> · pkg:gem/<name>   (NO release)

    For OS packages (rpm/deb) `release` is REQUIRED — if the user didn't say which release/codename,
    ASK before calling. For language ecosystems leave `release` empty.

    Returns the vulnerable CVEs, each with the fixed version, status, and which source said so.

    Args:
        purl: package URL identifying the product (see above; version may be omitted from the purl).
        version: the installed version string (e.g. "1.0.1e-30.el6_6.1", "2.25.1").
        release: distro release/codename — required for rpm/deb, leave empty for ecosystems.
    """
    res = await match_check(hasura, purl, version, release or None)
    cves = res["cves"]
    return {
        "vulnerable": bool(cves),
        "purl": purl,
        "version": version,
        "ecosystem": res["ecosystem"],
        "release": res["release"],
        "count": len(cves),
        "cves": cves,
    }


@mcp.tool()
async def match_bulk(components: list[dict]) -> dict:
    """Bulk version-check a whole scan's components against the affected data (public CVEs
    AND custom LVEs) in one call — for a scanner/agent that has many components.

    Each component is an object: {"purl"|"cpe": <identifier>, "version": <installed>, "release"?: <distro>}
      - purl:  pkg:rpm/redhat/openssl · pkg:deb/ubuntu/curl (release el9 / jammy / …) · pkg:pypi/django
      - cpe:   a CPE 2.3 string for Windows / Microsoft / binary software

    Returns, per component, a status ("vulnerable" | "compliant" | "unknown") and the
    matching CVEs (id, fixed version, status, source), plus summary counts.

    Args:
        components: list of {purl|cpe, version, release?} objects.
    """
    results = []
    for c in components:
        ident = c.get("purl") or c.get("cpe") or ""
        ver = c.get("version") or ""
        try:
            res = await match_check(hasura, ident, ver, c.get("release") or None)
            cves = res["cves"]
            results.append({"component": ident, "version": ver,
                            "status": "vulnerable" if cves else "compliant",
                            "count": len(cves), "cves": cves})
        except Exception as e:
            results.append({"component": ident, "version": ver, "status": "unknown", "error": str(e)})
    return {
        "total": len(results),
        "vulnerable": sum(1 for r in results if r["status"] == "vulnerable"),
        "compliant": sum(1 for r in results if r["status"] == "compliant"),
        "unknown": sum(1 for r in results if r["status"] == "unknown"),
        "results": results,
    }


@mcp.tool()
async def create_lve(product: str, title: str, fixed: str = "", introduced: str = "",
                     last_affected: str = "", severity: str = "", description: str = "",
                     version_scheme: str = "", status: str = "affected") -> dict:
    """Create a custom vulnerability entry (LVE) — your own "CVE" for something not in the
    public feeds (e.g. "Notepad++ < 8.7.4"). Once created it is matched immediately by
    check_vulnerable / match_bulk and survives rebuilds.

    Requires a token with the `lve_writer` role (mint one with
    `vdb create-token --role lve_writer`); a read-only token is rejected by the database.

    Args:
        product: the affected product — a purl (pkg:generic/notepad++, pkg:pypi/<name>, …)
                 or a CPE 2.3 string.
        title:   short description, e.g. "Notepad++ < 8.7.4 buffer overflow".
        fixed:   the version that fixes it (installed < fixed ⇒ vulnerable); omit for "no fix yet".
        introduced / last_affected: optional range bounds (last_affected = inclusive upper).
        severity / description: optional metadata.
        version_scheme: comparison scheme (rpm / deb / semver / pep440 / generic — default generic).
        status: canonical status (default "affected"; "fixed" pairs with a `fixed` version).
    """
    try:
        row = await _create_lve(hasura, product, title, fixed=fixed or None,
                                introduced=introduced or None, last_affected=last_affected or None,
                                severity=severity or None, description=description or None,
                                version_scheme=version_scheme or None, status=status)
        return {"created": True, **row}
    except Exception as e:
        return {"created": False, "error": str(e)}


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
        request_token.set(token)        # forward to Hasura → client role gates read/write
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
