import uuid

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidSignatureError, InvalidTokenError
from pydantic import BaseModel

from app.config import get_settings
from app.security.jwt_handler import decode_token
from app.security.revocation import is_user_access_revoked

bearer_scheme = HTTPBearer(auto_error=False)
settings = get_settings()


class CurrentUser(BaseModel):
    """Decoded JWT payload as a typed object."""

    sub: str  # user_id
    email: str
    aud: str | None = None  # app client_id
    scopes: list[str] = []


async def _get_explicitly_trusted_current_user(token: str) -> CurrentUser | None:
    """仅供本地联调：让显式信任的 dev auth 作为 access token 的最终裁决方。"""
    if settings.app_env != "development" or not settings.jwt_trusted_issuer:
        return None

    try:
        # 禁用环境代理，避免 bearer 被本机代理配置转发到信任域之外。
        async with httpx.AsyncClient(
            timeout=5.0,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get(
                f"{settings.jwt_trusted_issuer.rstrip('/')}/auth/userinfo",
                headers={"Authorization": f"Bearer {token}"},
            )
        if response.status_code != status.HTTP_200_OK:
            return None
        body = response.json()
        user_id = str(uuid.UUID(body["id"]))
        email = body["email"]
        is_superuser = body["is_superuser"]
        is_active = body["is_active"]
        if not isinstance(email, str) or not email.strip():
            return None
        if not isinstance(is_superuser, bool) or is_active is not True:
            return None
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        return None

    return CurrentUser(
        sub=user_id,
        email=email,
        scopes=["admin"] if is_superuser else [],
    )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> CurrentUser:
    """Extract and validate the current user from Bearer token."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials, verify_type="access")
    except InvalidTokenError as e:
        # 本地 headless auth 与 dev auth 使用不同签名密钥。优先走本地密钥与显式
        # JWKS；只有最终仍是签名不匹配时，才把原 token 交给已配置的 HTTPS dev
        # auth /userinfo 重新验证。生产配置禁止开启该信任边界。
        trusted_user = (
            await _get_explicitly_trusted_current_user(credentials.credentials)
            if isinstance(e, InvalidSignatureError)
            else None
        )
        if trusted_user is not None:
            return trusted_user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    # Single Logout: a stateless access token stays cryptographically valid until it expires,
    # so after a logout we must reject in-flight tokens issued before it (shared-Redis marker).
    if await is_user_access_revoked(payload["sub"], payload.get("iat")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return CurrentUser(
        sub=payload["sub"],
        email=payload.get("email", ""),
        aud=payload.get("aud"),
        scopes=payload.get("scopes", []),
    )


async def get_current_superuser(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Require superuser role."""
    if "admin" not in user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def require_scopes(*required: str):
    """Dependency factory: require specific scopes."""

    async def _checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        missing = set(required) - set(user.scopes)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scopes: {', '.join(missing)}",
            )
        return user

    return _checker
