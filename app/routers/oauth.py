import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import Application, User
from app.schemas import OAuthTokenExchangeRequest, TokenResponse
from app.services import auth_service, oauth_service
from app.utils.redis import consume_auth_code, store_auth_code

settings = get_settings()
router = APIRouter(prefix="/auth/oauth", tags=["OAuth"])


# ==================== Google ====================


@router.get("/google")
async def google_login(
    client_id: str = Query(..., description="Your app's client_id"),
    redirect_uri: str = Query(..., description="Frontend callback URL"),
):
    """Redirect user to Google OAuth consent screen."""
    state = await oauth_service.create_oauth_state(client_id, redirect_uri)
    url = oauth_service.get_google_auth_url(state)
    return RedirectResponse(url=url)


@router.get("/google/callback")
async def google_callback(
    code: str,
    state: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Google OAuth callback. Generates a one-time auth code and redirects to frontend."""
    if not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing state parameter")

    try:
        state_data = await oauth_service.verify_and_consume_state(state)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired state parameter")

    client_id = state_data.get("client_id")
    redirect_uri = state_data.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state payload")

    # Validate redirect_uri against registered application
    await _validate_redirect_uri(client_id, redirect_uri, db)

    try:
        user_info = await oauth_service.exchange_google_code(code)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Google OAuth failed: {e}")

    if not user_info.get("email"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not get email from Google")

    user = await auth_service.social_login(
        provider="google",
        provider_id=user_info["provider_id"],
        email=user_info["email"],
        name=user_info.get("name"),
        avatar_url=user_info.get("avatar_url"),
        db=db,
    )

    auth_code = await _create_auth_code(user, client_id, redirect_uri, provider="google")
    return RedirectResponse(url=f"{redirect_uri}?code={auth_code}", status_code=302)


# ==================== GitHub ====================


@router.get("/github")
async def github_login(
    client_id: str = Query(..., description="Your app's client_id"),
    redirect_uri: str = Query(..., description="Frontend callback URL"),
):
    """Redirect user to GitHub OAuth consent screen."""
    state = await oauth_service.create_oauth_state(client_id, redirect_uri)
    url = oauth_service.get_github_auth_url(state)
    return RedirectResponse(url=url)


@router.get("/github/callback")
async def github_callback(
    code: str,
    state: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """GitHub OAuth callback. Generates a one-time auth code and redirects to frontend."""
    if not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing state parameter")

    try:
        state_data = await oauth_service.verify_and_consume_state(state)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired state parameter")

    client_id = state_data.get("client_id")
    redirect_uri = state_data.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state payload")

    # Validate redirect_uri against registered application
    await _validate_redirect_uri(client_id, redirect_uri, db)

    try:
        user_info = await oauth_service.exchange_github_code(code)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"GitHub OAuth failed: {e}")

    if not user_info.get("email"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not get email from GitHub")

    user = await auth_service.social_login(
        provider="github",
        provider_id=user_info["provider_id"],
        email=user_info["email"],
        name=user_info.get("name"),
        avatar_url=user_info.get("avatar_url"),
        db=db,
    )

    auth_code = await _create_auth_code(user, client_id, redirect_uri, provider="github")
    return RedirectResponse(url=f"{redirect_uri}?code={auth_code}", status_code=302)


# ==================== Token Exchange ====================


@router.post("/token", response_model=TokenResponse)
async def exchange_code_for_tokens(
    payload: OAuthTokenExchangeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a one-time authorization code for access + refresh tokens."""
    code_data = await consume_auth_code(payload.code)
    if code_data is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired authorization code",
        )

    if code_data["app_client_id"] != payload.client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="client_id mismatch",
        )

    # Look up user
    result = await db.execute(select(User).where(User.id == code_data["user_id"]))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found or inactive")

    tokens = await auth_service._issue_tokens(user, payload.client_id, db)
    await auth_service._log_login(
        db, user.id, payload.client_id, code_data.get("provider", "oauth"), request, success=True
    )
    return tokens


# ==================== Helpers ====================


async def _validate_redirect_uri(client_id: str, redirect_uri: str, db: AsyncSession):
    """Verify the redirect_uri is registered for the given application."""
    result = await db.execute(
        select(Application).where(Application.client_id == client_id, Application.is_active == True)
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown client_id")
    if redirect_uri not in app.redirect_uris:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="redirect_uri not registered for this application")


async def _create_auth_code(user: User, client_id: str, redirect_uri: str, provider: str) -> str:
    """Generate a one-time auth code and store it in Redis."""
    code = secrets.token_urlsafe(32)
    await store_auth_code(
        code,
        {
            "user_id": str(user.id),
            "app_client_id": client_id,
            "redirect_uri": redirect_uri,
            "provider": provider,
        },
        settings.auth_code_expire_seconds,
    )
    return code
