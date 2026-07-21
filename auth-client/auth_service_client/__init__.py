"""
Auth Service Client SDK

Lightweight JWT validator for business services.
Business services pip install this to verify tokens issued by Auth Service.

Usage:
    from auth_service_client import JWTValidator, require_auth, require_scopes

    validator = JWTValidator(jwks_url="http://localhost:8100/.well-known/jwks.json")

    app = FastAPI()

    @app.get("/protected")
    async def protected(user=Depends(require_auth(validator))):
        return {"user_id": user.sub}
"""

from typing import TYPE_CHECKING, Any

from auth_service_client.validator import AuthenticatedUser, JWTValidator

if TYPE_CHECKING:
    from auth_service_client.dependencies import require_auth, require_scopes

__all__ = ["JWTValidator", "AuthenticatedUser", "require_auth", "require_scopes"]
__version__ = "0.3.0"

_FASTAPI_HELPERS = frozenset({"require_auth", "require_scopes"})


def __getattr__(name: str) -> Any:
    """仅在使用 FastAPI helpers 时加载可选依赖。"""
    if name not in _FASTAPI_HELPERS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    try:
        from auth_service_client.dependencies import require_auth, require_scopes
    except ModuleNotFoundError as error:
        if error.name == "fastapi" or (error.name and error.name.startswith("fastapi.")):
            raise ModuleNotFoundError(
                "FastAPI helpers require the optional dependency; "
                "install it with `pip install 'seanfield-auth-client[fastapi]'`."
            ) from error
        raise

    helpers = {"require_auth": require_auth, "require_scopes": require_scopes}
    globals().update(helpers)
    return helpers[name]


def __dir__() -> list[str]:
    return sorted({*globals(), *_FASTAPI_HELPERS})
