"""JWT Validator that verifies tokens using JWKS from the Auth Service."""

import time
from dataclasses import dataclass, field

import httpx
import jwt
from jwt import PyJWK


@dataclass
class AuthenticatedUser:
    """Decoded user information from a verified JWT."""

    sub: str  # user_id
    email: str = ""
    aud: str | None = None  # app client_id
    scopes: list[str] = field(default_factory=list)
    raw_payload: dict = field(default_factory=dict)


class JWTValidator:
    """
    Validates JWTs issued by Auth Service using its JWKS endpoint.

    Usage:
        validator = JWTValidator(jwks_url="http://auth-service:8100/.well-known/jwks.json")
        user = validator.verify(token_string)
    """

    def __init__(
        self,
        jwks_url: str,
        issuer: str | None = None,
        audience: str | None = None,
        cache_ttl: int = 300,  # seconds to cache JWKS
    ):
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.audience = audience
        self.cache_ttl = cache_ttl
        self._jwks_cache: dict | None = None
        self._cache_time: float = 0

    def _fetch_jwks(self) -> dict:
        """Fetch JWKS from the Auth Service (with caching)."""
        now = time.time()
        if self._jwks_cache and (now - self._cache_time) < self.cache_ttl:
            return self._jwks_cache

        resp = httpx.get(self.jwks_url, timeout=10)
        resp.raise_for_status()
        self._jwks_cache = resp.json()
        self._cache_time = now
        return self._jwks_cache

    async def _fetch_jwks_async(self) -> dict:
        """Async version of JWKS fetch."""
        now = time.time()
        if self._jwks_cache and (now - self._cache_time) < self.cache_ttl:
            return self._jwks_cache

        async with httpx.AsyncClient() as client:
            resp = await client.get(self.jwks_url, timeout=10)
            resp.raise_for_status()
            self._jwks_cache = resp.json()
            self._cache_time = now
            return self._jwks_cache

    def _get_signing_key(self, token: str) -> str:
        """Extract the signing key from JWKS matching the token's kid."""
        jwks = self._fetch_jwks()
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        for key_data in jwks.get("keys", []):
            if key_data.get("kid") == kid:
                key = PyJWK(key_data)
                return key.key

        raise jwt.InvalidTokenError(f"No matching key found for kid: {kid}")

    async def _get_signing_key_async(self, token: str) -> str:
        """Async version of signing key extraction."""
        jwks = await self._fetch_jwks_async()
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        for key_data in jwks.get("keys", []):
            if key_data.get("kid") == kid:
                key = PyJWK(key_data)
                return key.key

        raise jwt.InvalidTokenError(f"No matching key found for kid: {kid}")

    def verify(self, token: str) -> AuthenticatedUser:
        """Verify a JWT token synchronously and return the authenticated user."""
        signing_key = self._get_signing_key(token)

        options = {"verify_aud": bool(self.audience)}
        kwargs = {}
        if self.issuer:
            kwargs["issuer"] = self.issuer
        if self.audience:
            kwargs["audience"] = self.audience

        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            options=options,
            **kwargs,
        )

        return AuthenticatedUser(
            sub=payload["sub"],
            email=payload.get("email", ""),
            aud=payload.get("aud"),
            scopes=payload.get("scopes", []),
            raw_payload=payload,
        )

    async def verify_async(self, token: str) -> AuthenticatedUser:
        """Verify a JWT token asynchronously."""
        signing_key = await self._get_signing_key_async(token)

        options = {"verify_aud": bool(self.audience)}
        kwargs = {}
        if self.issuer:
            kwargs["issuer"] = self.issuer
        if self.audience:
            kwargs["audience"] = self.audience

        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            options=options,
            **kwargs,
        )

        return AuthenticatedUser(
            sub=payload["sub"],
            email=payload.get("email", ""),
            aud=payload.get("aud"),
            scopes=payload.get("scopes", []),
            raw_payload=payload,
        )
