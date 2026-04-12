from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel

from app.security.jwt_handler import decode_token

bearer_scheme = HTTPBearer(auto_error=False)


class CurrentUser(BaseModel):
    """Decoded JWT payload as a typed object."""

    sub: str  # user_id
    email: str
    aud: str | None = None  # app client_id
    scopes: list[str] = []


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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

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
