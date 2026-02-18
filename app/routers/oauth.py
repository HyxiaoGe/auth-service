from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas import TokenResponse
from app.services import auth_service, oauth_service

router = APIRouter(prefix="/auth/oauth", tags=["OAuth"])


# ==================== Google ====================


@router.get("/google")
async def google_login(
    client_id: str | None = Query(None, description="Your app's client_id for tracking"),
    redirect_uri: str | None = Query(None, description="Override redirect URI"),
):
    """Redirect user to Google OAuth consent screen."""
    url = oauth_service.get_google_auth_url(client_id=client_id, redirect_uri=redirect_uri)
    return RedirectResponse(url=url)


@router.get("/google/callback", response_model=TokenResponse)
async def google_callback(
    code: str,
    state: str | None = None,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Google OAuth callback. Exchanges code for user info and issues JWT tokens.

    In production, you'd typically redirect to your frontend with tokens in URL params
    or set them as HttpOnly cookies. For API mode, we return JSON directly.
    """
    try:
        user_info = await oauth_service.exchange_google_code(code)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Google OAuth failed: {e}")

    if not user_info.get("email"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not get email from Google")

    return await auth_service.social_login(
        provider="google",
        provider_id=user_info["provider_id"],
        email=user_info["email"],
        name=user_info.get("name"),
        avatar_url=user_info.get("avatar_url"),
        client_id=state,  # app client_id passed through OAuth state
        request=request,
        db=db,
    )


# ==================== GitHub ====================


@router.get("/github")
async def github_login(
    client_id: str | None = Query(None, description="Your app's client_id for tracking"),
    redirect_uri: str | None = Query(None, description="Override redirect URI"),
):
    """Redirect user to GitHub OAuth consent screen."""
    url = oauth_service.get_github_auth_url(client_id=client_id, redirect_uri=redirect_uri)
    return RedirectResponse(url=url)


@router.get("/github/callback", response_model=TokenResponse)
async def github_callback(
    code: str,
    state: str | None = None,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    GitHub OAuth callback. Exchanges code for user info and issues JWT tokens.
    """
    try:
        user_info = await oauth_service.exchange_github_code(code)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"GitHub OAuth failed: {e}")

    if not user_info.get("email"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not get email from GitHub")

    return await auth_service.social_login(
        provider="github",
        provider_id=user_info["provider_id"],
        email=user_info["email"],
        name=user_info.get("name"),
        avatar_url=user_info.get("avatar_url"),
        client_id=state,
        request=request,
        db=db,
    )
