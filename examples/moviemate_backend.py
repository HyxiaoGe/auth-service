"""
Example: MovieMate backend using Auth Client SDK

This shows how minimal the integration is for a business service.
Only 3 lines of auth-related code needed!
"""

from fastapi import FastAPI, Depends
from auth import JWTValidator, require_auth, require_scopes, AuthenticatedUser

# ============================================================
# 1. Initialize the validator (point to your Auth Service)
# ============================================================
validator = JWTValidator(
    jwks_url="http://localhost:8100/.well-known/jwks.json",
    # Optional: lock down to only accept tokens meant for this app
    # audience="app_your_moviemate_client_id",
)

app = FastAPI(title="MovieMate API")


# ============================================================
# 2. Use require_auth() to protect endpoints
# ============================================================
@app.get("/movies/recommendations")
async def get_recommendations(user: AuthenticatedUser = Depends(require_auth(validator))):
    """
    Protected endpoint - requires valid JWT from Auth Service.
    The 'user' object contains:
      - user.sub    → user ID
      - user.email  → user email
      - user.aud    → which app the token was issued for
      - user.scopes → user permissions
    """
    return {
        "user_id": user.sub,
        "recommendations": [
            {"title": "Inception", "score": 0.95},
            {"title": "Interstellar", "score": 0.92},
        ],
    }


@app.get("/admin/stats")
async def admin_stats(user: AuthenticatedUser = Depends(require_scopes(validator, "admin"))):
    """Admin-only endpoint - requires 'admin' scope in JWT."""
    return {"total_users": 1234, "movies_rated": 56789}


@app.get("/public/trending")
async def trending():
    """Public endpoint - no auth needed."""
    return {"trending": ["Oppenheimer", "Barbie", "Killers of the Flower Moon"]}


# ============================================================
# That's it! No login logic, no password handling, no OAuth code.
# Auth Service handles all of that centrally.
# ============================================================
