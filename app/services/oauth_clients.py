from authlib.integrations.httpx_client import AsyncOAuth2Client

from app.config import get_settings

settings = get_settings()


def create_google_client() -> AsyncOAuth2Client:
    return AsyncOAuth2Client(
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        redirect_uri=f"{settings.auth_base_url}/auth/oauth/google/callback",
    )


def create_github_client() -> AsyncOAuth2Client:
    return AsyncOAuth2Client(
        client_id=settings.github_client_id,
        client_secret=settings.github_client_secret,
        redirect_uri=f"{settings.auth_base_url}/auth/oauth/github/callback",
    )
