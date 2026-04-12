import json
import secrets

from app.services.oauth_clients import create_github_client, create_google_client
from app.utils.redis import get_redis

OAUTH_STATE_PREFIX = "oauth_state:"
OAUTH_STATE_TTL = 300  # 5 minutes


# ==================== State CSRF ====================


async def create_oauth_state(client_id: str, redirect_uri: str) -> str:
    """Generate a random state, store business data in Redis, return unpredictable state value."""
    state = secrets.token_urlsafe(32)
    r = await get_redis()
    await r.setex(
        f"{OAUTH_STATE_PREFIX}{state}",
        OAUTH_STATE_TTL,
        json.dumps({"client_id": client_id, "redirect_uri": redirect_uri}),
    )
    return state


async def verify_and_consume_state(state: str) -> dict:
    """Atomically read and delete state from Redis. Raises ValueError if invalid/expired."""
    r = await get_redis()
    raw = await r.getdel(f"{OAUTH_STATE_PREFIX}{state}")
    if raw is None:
        raise ValueError("Invalid or expired OAuth state")
    return json.loads(raw)


# ==================== Google ====================


def get_google_auth_url(state: str) -> str:
    """Generate Google OAuth authorization URL."""
    client = create_google_client()
    uri, _ = client.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        state=state,
        scope="openid email profile",
        access_type="offline",
        prompt="consent",
    )
    return uri


async def exchange_google_code(code: str) -> dict:
    """Exchange Google authorization code for user info."""
    async with create_google_client() as client:
        await client.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
            redirect_uri=client.redirect_uri,
        )
        resp = await client.get("https://www.googleapis.com/oauth2/v2/userinfo")
        resp.raise_for_status()
        userinfo = resp.json()
        return {
            "provider_id": userinfo["id"],
            "email": userinfo["email"],
            "name": userinfo.get("name"),
            "avatar_url": userinfo.get("picture"),
        }


# ==================== GitHub ====================


def get_github_auth_url(state: str) -> str:
    """Generate GitHub OAuth authorization URL."""
    client = create_github_client()
    uri, _ = client.create_authorization_url(
        "https://github.com/login/oauth/authorize",
        state=state,
        scope="read:user user:email",
    )
    return uri


async def exchange_github_code(code: str) -> dict:
    """Exchange GitHub authorization code for user info."""
    async with create_github_client() as client:
        await client.fetch_token(
            "https://github.com/login/oauth/access_token",
            code=code,
            headers={"Accept": "application/json"},
        )
        resp = await client.get(
            "https://api.github.com/user",
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        user = resp.json()

        email = user.get("email")
        if not email:
            email_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={"Accept": "application/json"},
            )
            email_resp.raise_for_status()
            emails = email_resp.json()
            primary = next((e for e in emails if e.get("primary")), emails[0] if emails else None)
            email = primary["email"] if primary else None

        return {
            "provider_id": str(user["id"]),
            "email": email,
            "name": user.get("name") or user.get("login"),
            "avatar_url": user.get("avatar_url"),
        }
