"""FastAPI dependency factories for the Auth Client SDK."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth.validator import AuthenticatedUser, JWTValidator

_bearer = HTTPBearer(auto_error=False)


def require_auth(validator: JWTValidator):
    """
    FastAPI dependency: require a valid JWT token.

    Usage:
        validator = JWTValidator(jwks_url="...")

        @app.get("/protected")
        async def protected(user=Depends(require_auth(validator))):
            return {"user_id": user.sub}
    """

    async def _dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> AuthenticatedUser:
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            return await validator.verify_async(credentials.credentials)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {e}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e

    return _dependency


def require_scopes(validator: JWTValidator, *scopes: str):
    """
    FastAPI dependency: require specific scopes in the JWT.

    Usage:
        @app.delete("/admin/item")
        async def delete_item(user=Depends(require_scopes(validator, "admin"))):
            ...
    """

    async def _dependency(
        user: AuthenticatedUser = Depends(require_auth(validator)),
    ) -> AuthenticatedUser:
        missing = set(scopes) - set(user.scopes)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scopes: {', '.join(missing)}",
            )
        return user

    return _dependency
