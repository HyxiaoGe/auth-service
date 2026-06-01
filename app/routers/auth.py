import uuid
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Application, User, UserPreference
from app.schemas import (
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    ProfileUpdateRequest,
    RefreshRequest,
    RegisterRequest,
    RevokeRequest,
    TokenResponse,
    UserInfo,
    UserPreferencesResponse,
)
from app.security.deps import CurrentUser, get_current_user
from app.services import auth_service, oauth_service, session_service
from app.utils.redis import delete_session, get_session

router = APIRouter(prefix="/auth", tags=["Authentication"])


def oauth_error(
    error: str,
    error_description: str,
    redirect_uri: str | None = None,
    state: str | None = None,
):
    """Unified OAuth/OIDC error response.

    Before redirect_uri is validated (bad client_id/redirect_uri/response_type) we must
    NOT redirect anywhere -- return a 400 JSON ``{error, error_description}``. After the
    redirect_uri is known-good, errors go back to the app as
    ``302 {redirect_uri}?error=&error_description=&state=`` so the SDK can react. ``state``
    is echoed only when present.
    """
    if redirect_uri is None:
        return JSONResponse(
            status_code=400,
            content={"error": error, "error_description": error_description},
        )
    params = {"error": error, "error_description": error_description}
    if state is not None:
        params["state"] = state
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user with email and password."""
    await auth_service.register_user(payload, db)
    # Auto-login after registration
    login_payload = LoginRequest(email=payload.email, password=payload.password)
    return await auth_service.login_user(login_payload, request, db)


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Login with email and password. Optionally pass client_id to identify the app."""
    return await auth_service.login_user(payload, request, db)


@router.post("/token/refresh", response_model=TokenResponse)
async def refresh_token(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a refresh token for a new token pair (rotation enabled)."""
    return await auth_service.refresh_access_token(payload.refresh_token, db)


@router.post("/token/revoke", response_model=MessageResponse)
async def revoke_token(
    payload: RevokeRequest,
    db: AsyncSession = Depends(get_db),
):
    """Revoke a refresh token (logout)."""
    await auth_service.revoke_refresh_token(payload.refresh_token, db)
    return MessageResponse(message="Token revoked successfully")


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    payload: LogoutRequest | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Single Logout: destroy the IdP session, revoke all refresh tokens, clear the cookie.

    POST-only (never GET) so it cannot be triggered by a cross-site <img>/navigation.
    Note: already-issued access tokens are stateless 15-min JWTs and remain valid until
    they expire -- revoking refresh tokens stops *new* access tokens from being minted.
    """
    sid = session_service.read_sid(request)
    session = await get_session(sid) if sid else None
    if session:
        user_id = session.get("user_id")
        if user_id:
            await auth_service._revoke_all_user_tokens(uuid.UUID(user_id), db)
    if sid:
        await delete_session(sid)

    if (
        payload
        and payload.post_logout_redirect_uri
        and await _is_registered_redirect(payload.post_logout_redirect_uri, db)
    ):
        redirect = RedirectResponse(url=payload.post_logout_redirect_uri, status_code=302)
        session_service.clear_session_cookie(redirect)
        return redirect

    session_service.clear_session_cookie(response)
    return MessageResponse(message="Logged out")


async def _is_registered_redirect(uri: str, db: AsyncSession) -> bool:
    """True if uri is a registered redirect_uri of some active app (open-redirect guard)."""
    result = await db.execute(select(Application).where(Application.is_active.is_(True)))
    return any(uri in app.redirect_uris for app in result.scalars())


async def _resolve_authorize_app(client_id: str, redirect_uri: str, db: AsyncSession) -> Application | None:
    """Return the active Application iff redirect_uri is an exact registered match, else None."""
    result = await db.execute(
        select(Application).where(Application.client_id == client_id, Application.is_active.is_(True))
    )
    app = result.scalar_one_or_none()
    if app is None or redirect_uri not in app.redirect_uris:
        return None
    return app


@router.get("/authorize")
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    prompt: str | None = None,
    provider: str | None = None,
    nonce: str | None = None,
    scope: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """SSO front door (OIDC-aligned authorization endpoint).

    A live IdP session yields a silent auth code (no social round-trip = SSO); otherwise
    the user is sent through interactive login -- unless ``prompt=none``, which fails
    silently with ``login_required`` so apps can probe for an existing session without UI.

    Validation order matters: response_type and client_id/redirect_uri are checked before
    anything with side effects, and we NEVER redirect to an unvalidated redirect_uri. PKCE
    (S256) is mandatory here -- this endpoint is new, so requiring it breaks no existing app.
    """
    # 0. response_type — block deprecated implicit/hybrid (OAuth 2.0 BCP)
    if response_type != "code":
        return oauth_error("unsupported_response_type", "only response_type=code is supported")

    # 1. client_id + redirect_uri (exact match) — before any side effect / before any redirect
    app = await _resolve_authorize_app(client_id, redirect_uri, db)
    if app is None:
        return oauth_error("invalid_client", "unknown client_id or unregistered redirect_uri")

    # 2. PKCE mandatory (public clients) — redirect_uri is validated, so errors go back to the app
    if not code_challenge or code_challenge_method != "S256":
        return oauth_error(
            "invalid_request", "PKCE required: code_challenge + code_challenge_method=S256", redirect_uri, state
        )

    # 3. resolve the IdP session (slides TTL, enforces absolute lifetime)
    _sid, session = await session_service.resolve_session(request)

    # 4. silent SSO — a live session and no forced re-auth
    if session and prompt not in ("login", "select_account"):
        amr = session.get("amr") or ["sso"]
        code = await oauth_service.mint_auth_code(
            user_id=session["user_id"],
            client_id=client_id,
            redirect_uri=redirect_uri,
            provider=amr[0],
            code_challenge=code_challenge,
        )
        params = {"code": code}
        if state is not None:
            params["state"] = state
        return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)

    # 5. interaction required
    if prompt == "none":
        return oauth_error("login_required", "no active session", redirect_uri, state)

    if provider not in ("google", "github"):
        # MVP: the app's SDK renders its own provider buttons, so a no-provider interactive
        # hit is bounced back for the app to handle (a hosted chooser page is deferred).
        return oauth_error("invalid_request", "provider is required", redirect_uri, state)

    # carry the full authorize context across the social round-trip (app_state rides along,
    # never sent upstream); the callback resumes from here and echoes app_state back.
    oauth_state = await oauth_service.create_oauth_state(
        client_id,
        redirect_uri,
        app_state=state,
        prompt=prompt,
        provider=provider,
        response_type=response_type,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
    )
    if provider == "google":
        url = oauth_service.get_google_auth_url(oauth_state, prompt=prompt)
    else:
        url = oauth_service.get_github_auth_url(oauth_state)
    return RedirectResponse(url=url, status_code=302)


def _build_preferences(pref: UserPreference | None) -> UserPreferencesResponse:
    if pref is None:
        return UserPreferencesResponse()
    return UserPreferencesResponse(
        locale=pref.locale,
        timezone=pref.timezone,
        theme=pref.theme,
    )


@router.get("/userinfo", response_model=UserInfo)
async def get_userinfo(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user info from the access token."""
    from sqlalchemy.orm import selectinload

    result = await db.execute(select(User).options(selectinload(User.preferences)).where(User.id == user.sub))
    db_user = result.scalar_one_or_none()
    if not db_user:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserInfo(
        id=db_user.id,
        email=db_user.email,
        name=db_user.name,
        avatar_url=db_user.avatar_url,
        is_superuser=db_user.is_superuser,
        is_active=db_user.is_active,
        created_at=db_user.created_at,
        preferences=_build_preferences(db_user.preferences),
    )


@router.patch("/profile", response_model=UserInfo)
async def update_profile(
    payload: ProfileUpdateRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update current user's profile and preferences."""
    from sqlalchemy.orm import selectinload

    result = await db.execute(select(User).options(selectinload(User.preferences)).where(User.id == user.sub))
    db_user = result.scalar_one_or_none()
    if not db_user:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Update profile fields
    if payload.name is not None:
        db_user.name = payload.name
    if payload.avatar_url is not None:
        db_user.avatar_url = payload.avatar_url

    # Update preferences
    has_pref_update = any(v is not None for v in [payload.locale, payload.timezone, payload.theme])
    if has_pref_update:
        pref = db_user.preferences
        if pref is None:
            pref = UserPreference(user_id=db_user.id)
            db.add(pref)
            db_user.preferences = pref
        if payload.locale is not None:
            pref.locale = payload.locale
        if payload.timezone is not None:
            pref.timezone = payload.timezone
        if payload.theme is not None:
            pref.theme = payload.theme

    await db.commit()
    await db.refresh(db_user)
    # Re-load preferences after commit
    result = await db.execute(select(User).options(selectinload(User.preferences)).where(User.id == db_user.id))
    db_user = result.scalar_one_or_none()

    return UserInfo(
        id=db_user.id,
        email=db_user.email,
        name=db_user.name,
        avatar_url=db_user.avatar_url,
        is_superuser=db_user.is_superuser,
        is_active=db_user.is_active,
        created_at=db_user.created_at,
        preferences=_build_preferences(db_user.preferences),
    )
