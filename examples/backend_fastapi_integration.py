"""
Example: backend (FastAPI) integration with the shared auth-client SDK.

Install:
    pip install "auth-client[fastapi] @ git+https://github.com/HyxiaoGe/auth-service.git@auth-client-v0.2.0#subdirectory=auth-client"

The SDK (`auth-client`) does exactly one thing: verify an RS256 access token against the
IdP's JWKS and return an `AuthenticatedUser`. Everything else is your app's job:

  * build ONE validator from env (with issuer + audience + token-type hardening),
  * map the SDK's `AuthenticatedUser` to YOUR OWN user type (don't leak the SDK type),
  * translate verification failures into your error envelope,
  * (optionally) enrich from /auth/userinfo and upsert a local user row.

This file is a copy-paste starting point. See docs/AUTH_CONTRACT.md for the wire contract.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from auth import JWTValidator  # from the auth-client SDK
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# 1. Config (env-driven)
# ---------------------------------------------------------------------------
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "http://localhost:8100")
AUTH_SERVICE_CLIENT_ID = os.environ.get("AUTH_SERVICE_CLIENT_ID", "")
AUTH_SERVICE_JWKS_URL = os.environ.get(
    "AUTH_SERVICE_JWKS_URL", f"{AUTH_SERVICE_URL.rstrip('/')}/.well-known/jwks.json"
)

# ---------------------------------------------------------------------------
# 2. One validator, built lazily (easy to patch in tests; no import-time env reads)
# ---------------------------------------------------------------------------
_validator: JWTValidator | None = None


def get_validator() -> JWTValidator:
    global _validator
    if _validator is None:
        _validator = JWTValidator(
            jwks_url=AUTH_SERVICE_JWKS_URL,
            issuer=AUTH_SERVICE_URL,            # reject tokens from another issuer
            audience=AUTH_SERVICE_CLIENT_ID,    # reject tokens minted for another app
            require_token_type="access",        # reject refresh tokens on protected routes
            cache_ttl=300,
        )
    return _validator


# ---------------------------------------------------------------------------
# 3. Your own user type + a thin dependency that returns it (never the SDK type)
# ---------------------------------------------------------------------------
@dataclass
class CurrentUser:
    id: str
    email: str
    scopes: list[str]
    name: str | None = None
    avatar_url: str | None = None
    is_admin: bool = False


_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> CurrentUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        # Translate into YOUR error envelope/codes here.
        raise HTTPException(status_code=401, detail="auth token not provided")

    try:
        user = await get_validator().verify_async(credentials.credentials)
    except Exception as exc:  # auth-client raises jwt.InvalidTokenError (& subclasses)
        # Distinguish expired vs invalid for a friendlier message if you like.
        detail = "token expired" if "expired" in str(exc).lower() else "invalid token"
        raise HTTPException(status_code=401, detail=detail) from exc

    # name / avatar_url are NOT first-class SDK fields — read them from raw_payload,
    # or fetch GET /auth/userinfo and/or upsert a local user row here (app-side).
    return CurrentUser(
        id=user.sub,
        email=user.email,
        scopes=user.scopes,
        name=user.raw_payload.get("name"),
        avatar_url=user.raw_payload.get("avatar_url"),
        is_admin="admin" in user.scopes,
    )


async def get_admin_user(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="permission denied")
    return user


# ---------------------------------------------------------------------------
# 4. Use it
# ---------------------------------------------------------------------------
app = FastAPI(title="My App API")


@app.get("/public")
async def public():
    return {"message": "anyone can see this"}


@app.get("/me")
async def me(user: CurrentUser = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "scopes": user.scopes}


@app.get("/admin/stats")
async def admin_stats(_: CurrentUser = Depends(get_admin_user)):
    return {"ok": True}
