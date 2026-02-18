from urllib.parse import urlencode

import httpx

from app.config import get_settings

settings = get_settings()


# ==================== Google OAuth ====================


def get_google_auth_url(client_id: str | None = None, redirect_uri: str | None = None) -> str:
    """Generate Google OAuth authorization URL."""
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": redirect_uri or f"{settings.auth_base_url}/auth/oauth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    if client_id:
        params["state"] = client_id  # pass app client_id through state
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"


async def exchange_google_code(code: str, redirect_uri: str | None = None) -> dict:
    """Exchange Google authorization code for tokens and user info."""
    async with httpx.AsyncClient() as client:
        # Exchange code for tokens
        token_resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": redirect_uri or f"{settings.auth_base_url}/auth/oauth/google/callback",
                "grant_type": "authorization_code",
            },
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

        # Get user info
        userinfo_resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()

    return {
        "provider_id": userinfo["id"],
        "email": userinfo["email"],
        "name": userinfo.get("name"),
        "avatar_url": userinfo.get("picture"),
    }


# ==================== GitHub OAuth ====================


def get_github_auth_url(client_id: str | None = None, redirect_uri: str | None = None) -> str:
    """Generate GitHub OAuth authorization URL."""
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": redirect_uri or f"{settings.auth_base_url}/auth/oauth/github/callback",
        "scope": "read:user user:email",
    }
    if client_id:
        params["state"] = client_id
    return f"https://github.com/login/oauth/authorize?{urlencode(params)}"


async def exchange_github_code(code: str, redirect_uri: str | None = None) -> dict:
    """Exchange GitHub authorization code for tokens and user info."""
    async with httpx.AsyncClient() as client:
        # Exchange code for token
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": redirect_uri or f"{settings.auth_base_url}/auth/oauth/github/callback",
            },
            headers={"Accept": "application/json"},
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

        access_token = tokens["access_token"]

        # Get user info
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_resp.raise_for_status()
        user = user_resp.json()

        # Get primary email (may not be public)
        email = user.get("email")
        if not email:
            email_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}"},
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
