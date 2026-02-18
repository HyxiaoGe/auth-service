"""
Auth Client SDK

Lightweight JWT validator for business services.
Business services pip install this to verify tokens issued by Auth Service.

Usage:
    from auth import JWTValidator, require_auth, require_scopes

    validator = JWTValidator(jwks_url="http://localhost:8100/.well-known/jwks.json")

    app = FastAPI()

    @app.get("/protected")
    async def protected(user=Depends(require_auth(validator))):
        return {"user_id": user.sub}
"""

from auth.validator import JWTValidator, AuthenticatedUser
from auth.dependencies import require_auth, require_scopes

__all__ = ["JWTValidator", "AuthenticatedUser", "require_auth", "require_scopes"]
__version__ = "0.1.0"
