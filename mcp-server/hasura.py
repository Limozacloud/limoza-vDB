"""Thin async GraphQL client for the read-only Hasura API.

Authentication reuses the exact same mechanism as every other GraphQL consumer:
either a pre-minted read-only token (`GRAPHQL_TOKEN`) or a short-lived JWT minted
from the shared `HASURA_JWT_SECRET` — identical claims to the `create-token` CLI
(role `readonly`). If neither is configured, requests fall back to the anonymous
role (works when Hasura keeps `HASURA_GRAPHQL_UNAUTHORIZED_ROLE=anonymous`).
"""

import contextvars
import datetime
import secrets

import httpx
import jwt as pyjwt

from config import Settings

# The calling client's bearer token, stashed per-request by the auth middleware. When
# set it is forwarded to Hasura verbatim, so the client's ROLE governs read vs write
# (readonly can only read; lve_writer can also insert LVEs) — Hasura enforces it.
request_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_token", default=None)


class HasuraClient:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._client = httpx.AsyncClient(timeout=30.0)
        self._minted: tuple[str, datetime.datetime] | None = None

    async def aclose(self) -> None:
        await self._client.aclose()

    def _bearer(self) -> str | None:
        # (0) Forward the calling client's token when present → its role gates read/write.
        tok = request_token.get()
        if tok:
            return tok
        # (a) Reuse a token handed in verbatim — same token the GraphQL API uses.
        if self._s.graphql_token:
            return self._s.graphql_token
        # Otherwise mint a read-only JWT from the shared signing key.
        if not self._s.jwt_secret:
            return None  # anonymous role
        now = datetime.datetime.now(datetime.timezone.utc)
        if self._minted and (self._minted[1] - now) > datetime.timedelta(seconds=60):
            return self._minted[0]
        exp = now + datetime.timedelta(days=self._s.token_ttl_days)
        payload = {
            "jti": secrets.token_hex(16),
            "iat": now,
            "exp": exp,
            "https://hasura.io/jwt/claims": {
                "x-hasura-allowed-roles": ["readonly"],
                "x-hasura-default-role": "readonly",
            },
        }
        token = pyjwt.encode(payload, self._s.jwt_secret, algorithm="HS256")
        self._minted = (token, exp)
        return token

    async def query(self, query: str, variables: dict) -> dict:
        headers = {}
        bearer = self._bearer()
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        resp = await self._client.post(
            self._s.graphql_url,
            json={"query": query, "variables": variables},
            headers=headers,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            raise RuntimeError(f"GraphQL error: {body['errors']}")
        return body["data"]
