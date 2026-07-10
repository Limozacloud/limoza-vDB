"""Runtime configuration, read entirely from environment variables.

Nothing here is shared with the ingest code — the MCP server is self-contained and
only needs to know how to reach Hasura and how to authenticate clients.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Where this MCP server listens (inside the container).
    host: str
    port: int
    # Bearer token clients must present to call the MCP endpoint.
    # None disables auth (development only — logged as a warning).
    auth_token: str | None
    # Hasura GraphQL endpoint (network-internal in Compose: http://hasura:8080/v1/graphql).
    graphql_url: str
    # The REST API's /match endpoint (network-internal in Compose: http://api:8770) — the
    # matcher itself lives there; the MCP tools call it instead of duplicating the logic.
    api_url: str
    # Option 1 (a): use a pre-minted read-only token verbatim (same one the GraphQL API uses).
    graphql_token: str | None
    # Option 2: mint a short-lived read-only JWT from the shared Hasura signing key.
    jwt_secret: str | None
    token_ttl_days: int


def load_settings() -> Settings:
    return Settings(
        host=os.environ.get("MCP_HOST", "0.0.0.0"),
        port=int(os.environ.get("MCP_PORT", "8765")),
        auth_token=os.environ.get("MCP_AUTH_TOKEN") or None,
        graphql_url=os.environ.get("GRAPHQL_URL", "http://hasura:8080/v1/graphql"),
        api_url=os.environ.get("API_URL", "http://api:8770"),
        graphql_token=os.environ.get("GRAPHQL_TOKEN") or None,
        jwt_secret=os.environ.get("HASURA_JWT_SECRET") or None,
        token_ttl_days=int(os.environ.get("GRAPHQL_TOKEN_TTL_DAYS", "1")),
    )
