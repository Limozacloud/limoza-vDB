"""Thin async client for the REST /match endpoint.

The matcher itself lives in the ingest service (`ingest/match`), served over REST by
`ingest/api.py`. Rather than duplicating that logic here, the MCP tools call it directly —
one matcher, three callers (CLI, REST, MCP). Auth mirrors `hasura.py`: forward the calling
client's bearer token (its role gates what it can do — /match accepts any valid token), or
mint a short-lived readonly JWT from the shared `HASURA_JWT_SECRET`.
"""
import datetime
import secrets

import httpx
import jwt as pyjwt

from config import Settings
from hasura import request_token


class ApiClient:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._client = httpx.AsyncClient(timeout=30.0)
        self._minted: tuple[str, datetime.datetime] | None = None

    async def aclose(self) -> None:
        await self._client.aclose()

    def _bearer(self) -> str | None:
        tok = request_token.get()
        if tok:
            return tok
        if self._s.graphql_token:
            return self._s.graphql_token
        if not self._s.jwt_secret:
            return None  # unauthenticated (dev only — matches the API's own fallback)
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

    async def match(self, components: list[dict]) -> dict:
        headers = {}
        bearer = self._bearer()
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        resp = await self._client.post(
            f"{self._s.api_url}/match", json={"components": components}, headers=headers)
        resp.raise_for_status()
        return resp.json()
