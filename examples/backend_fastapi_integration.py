"""
Example: backend (FastAPI) integration with the shared auth-client SDK.

Install:
    pip install "seanfield-auth-client[fastapi]==0.3.0"

The SDK (`seanfield-auth-client`, imported as `auth_service_client`) does exactly one
thing: verify an RS256 access token against the
IdP's JWKS and return an `AuthenticatedUser`. Everything else is your app's job:

  * build ONE validator from env (with issuer + audience + token-type hardening),
  * map the SDK's `AuthenticatedUser` to YOUR OWN user type (don't leak the SDK type),
  * translate verification failures into your error envelope,
  * (optionally) enrich from /auth/userinfo and upsert a local user row.

For immediate cross-app/session revocation, also check `revoked_sid:{sid}` and
`revoked_user:{sub}` in the Auth Service's shared Redis after JWT verification. The SDK
does not connect to Redis; without that application-side check, an access token remains
valid until its configured `exp`. See docs/INTEGRATION_GUIDE.md section 7.1.

This file is a copy-paste starting point. See docs/AUTH_CONTRACT.md for the wire contract.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from auth_service_client import JWTValidator
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# 1. Config (env-driven and fail-fast)
# ---------------------------------------------------------------------------
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "").strip().rstrip("/")
AUTH_SERVICE_CLIENT_ID = os.environ.get("AUTH_SERVICE_CLIENT_ID", "").strip()
if not AUTH_SERVICE_URL or not AUTH_SERVICE_CLIENT_ID:
    raise RuntimeError("AUTH_SERVICE_URL and AUTH_SERVICE_CLIENT_ID are required")
AUTH_SERVICE_JWKS_URL = os.environ.get(
    "AUTH_SERVICE_JWKS_URL", f"{AUTH_SERVICE_URL}/.well-known/jwks.json"
).strip()
if not AUTH_SERVICE_JWKS_URL:
    raise RuntimeError("AUTH_SERVICE_JWKS_URL must not be empty")

# ---------------------------------------------------------------------------
# 2. One validator, built lazily
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
