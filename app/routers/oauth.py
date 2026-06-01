from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Application, User
from app.schemas import OAuthTokenExchangeRequest, TokenResponse
from app.services import auth_service, oauth_service, session_service
from app.utils.redis import consume_auth_code

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
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired state parameter"
        ) from err

    client_id = state_data.get("client_id")
    redirect_uri = state_data.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state payload")

    # Validate redirect_uri against registered application
    await _validate_redirect_uri(client_id, redirect_uri, db)

    try:
        user_info = await oauth_service.exchange_google_code(code)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Google OAuth failed: {e}") from e

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

    return await _social_redirect(user, state_data, provider="google")


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
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired state parameter"
        ) from err

    client_id = state_data.get("client_id")
    redirect_uri = state_data.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state payload")

    # Validate redirect_uri against registered application
    await _validate_redirect_uri(client_id, redirect_uri, db)

    try:
        user_info = await oauth_service.exchange_github_code(code)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"GitHub OAuth failed: {e}") from e

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

    return await _social_redirect(user, state_data, provider="github")


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

    _enforce_pkce(code_data, payload.code_verifier)

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


def _enforce_pkce(code_data: dict, code_verifier: str | None) -> None:
    """Conditional PKCE gate (RFC 7636, S256).

    Enforce a code_verifier ONLY when the auth code was minted with a code_challenge --
    that is, when it came through /authorize. Codes from the legacy direct
    /oauth/{provider} flow carry no challenge and pass through untouched, so existing
    apps keep working without a verifier (zero-breakage).
    """
    challenge = code_data.get("code_challenge")
    if not challenge:
        return
    if not code_verifier or not oauth_service.verify_pkce(code_verifier, challenge):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: PKCE verification failed",
        )


async def _validate_redirect_uri(client_id: str, redirect_uri: str, db: AsyncSession):
    """Verify the redirect_uri is registered for the given application."""
    result = await db.execute(
        select(Application).where(Application.client_id == client_id, Application.is_active.is_(True))
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown client_id")
    if redirect_uri not in app.redirect_uris:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="redirect_uri not registered for this application"
        )


async def _social_redirect(user: User, state_data: dict, provider: str) -> RedirectResponse:
    """Finish a social login: mint the auth code, establish the IdP session, redirect back.

    When the flow originated at /authorize, ``state_data`` carries ``app_state`` (echoed
    back as ``?state=``) and ``code_challenge`` (bound into the code so /token enforces
    PKCE). The legacy direct flow carries neither, so this yields a bare ``?code=`` and an
    unbound code -- exactly the prior behavior (zero-breakage).

    The session cookie must be set on this inline RedirectResponse (not via Depends):
    ``social_login()`` returns a ``User``, not a ``Response``.
    """
    redirect_uri = state_data["redirect_uri"]
    code = await oauth_service.mint_auth_code(
        user_id=str(user.id),
        client_id=state_data["client_id"],
        redirect_uri=redirect_uri,
        provider=provider,
        code_challenge=state_data.get("code_challenge"),
    )
    params = {"code": code}
    app_state = state_data.get("app_state")
    if app_state is not None:
        params["state"] = app_state
    response = RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)
    await session_service.start_session(response, str(user.id), [provider])
    return response
