import json
import logging
import re
import time
import uuid
from ipaddress import ip_address
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from app.config import get_settings
from app.database import get_db
from app.models import Application, User, UserPreference
from app.schemas import (
    EmailHeadlessSendRequest,
    EmailHeadlessStartRequest,
    EmailHeadlessVerifyRequest,
    LoginRequest,
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
from app.security.revocation import revoke_user_access_tokens
from app.services import auth_service, email_login_service, email_sender, oauth_service, session_service
from app.services.email_sender import EmailSender, get_email_sender
from app.utils.oauth_redirect import oauth_redirect
from app.utils.origin import schemeful_web_origin_same_site
from app.utils.redirect_uri import oauth_redirect_origin, oauth_redirect_uri_allowed
from app.utils.redis import delete_session, get_session

router = APIRouter(prefix="/auth", tags=["Authentication"])

logger = logging.getLogger(__name__)

settings = get_settings()

_HEADLESS_S256_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_HEADLESS_STATE = re.compile(r"[A-Za-z0-9_-]{32,2048}")


@router.get("/capabilities")
async def capabilities(
    request: Request,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """公开返回可安全展示的认证能力，不暴露 SMTP 等内部配置。"""
    email_login_available = email_sender.is_email_login_available(settings)
    headless_login_available = False
    if (
        client_id
        and redirect_uri
        and settings.email_headless_login_enabled
        and email_login_available
        and _headless_origin_matches(request, redirect_uri)
        and await _resolve_authorize_app(client_id, redirect_uri, db) is not None
    ):
        headless_login_available = True
    return JSONResponse(
        content={
            # 兼容旧客户端的响应结构，但 hosted 邮箱登录已下线。
            "email_login": False,
            "email_headless_login": headless_login_available,
        },
        headers={"Cache-Control": "no-store", "Vary": "Origin"},
    )


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
    return oauth_redirect(redirect_uri, params)


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


def _email_browser_cookie(request: Request) -> str | None:
    return request.cookies.get(email_login_service.email_browser_cookie_name(settings))


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    try:
        return str(ip_address(candidate))
    except ValueError:
        return None


def _email_client_ip(request: Request) -> str:
    peer = _valid_ip(request.client.host if request.client else None)
    if peer is None:
        return "unknown"
    peer_address = ip_address(peer)
    if not any(peer_address in network for network in settings.trusted_proxy_networks):
        return peer
    forwarded_hops = [
        valid
        for value in request.headers.get("x-forwarded-for", "").split(",")
        if (valid := _valid_ip(value)) is not None
    ]
    for hop in reversed(forwarded_hops):
        hop_address = ip_address(hop)
        if not any(hop_address in network for network in settings.trusted_proxy_networks):
            return hop
    return peer


def _headless_json(
    content: dict,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    background: BackgroundTask | None = None,
) -> JSONResponse:
    response = JSONResponse(content=content, status_code=status_code, headers=headers, background=background)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Vary"] = "Origin"
    return response


def _headless_error(
    error: str,
    error_description: str,
    *,
    status_code: int,
    state: str | None = None,
    retry_after: int = 0,
) -> JSONResponse:
    content: dict[str, str | int] = {"error": error, "error_description": error_description}
    if state is not None:
        content["state"] = state
    headers = None
    if retry_after:
        content["retry_after"] = retry_after
        headers = {"Retry-After": str(retry_after)}
    return _headless_json(content, status_code=status_code, headers=headers)


def _headless_origin_matches(request: Request, redirect_uri: str) -> bool:
    origin = request.headers.get("origin")
    return bool(
        origin
        and origin != "null"
        and _headless_web_origin_allowed(origin)
        and schemeful_web_origin_same_site(settings.auth_base_url, origin)
        and origin in settings.cors_origin_list
        and origin == oauth_redirect_origin(redirect_uri)
    )


def _headless_web_origin_allowed(origin: str | None) -> bool:
    if not origin or origin == "null":
        return False
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"}:
        return False
    return oauth_redirect_uri_allowed(origin) and oauth_redirect_origin(origin) == origin


async def _validated_headless_email_flow(request: Request, flow_id: str) -> dict | None:
    origin = request.headers.get("origin")
    if not _headless_web_origin_allowed(origin) or origin not in settings.cors_origin_list:
        logger.warning("email_login.headless_validation_failed reason=origin_not_allowed")
        return None
    browser_cookie = _email_browser_cookie(request)
    if not browser_cookie:
        logger.warning("email_login.headless_validation_failed reason=browser_cookie_missing")
        return None
    flow = await email_login_service.get_bound_email_flow(flow_id, browser_cookie, config=settings)
    if flow is None:
        logger.warning("email_login.headless_validation_failed reason=flow_binding_mismatch")
        return None
    if not _headless_origin_matches(request, flow["redirect_uri"]):
        logger.warning("email_login.headless_validation_failed reason=origin_mismatch")
        return None
    if not email_login_service.email_flow_csrf_matches(flow, request.headers.get("x-csrf-token"), settings):
        logger.warning("email_login.headless_validation_failed reason=csrf_mismatch")
        return None
    return flow


async def _expired_headless_email_flow_response(
    request: Request,
    flow_id: str,
    db: AsyncSession,
) -> JSONResponse | None:
    origin = request.headers.get("origin")
    if not _headless_web_origin_allowed(origin) or origin not in settings.cors_origin_list:
        return None
    recovery = await email_login_service.get_bound_email_flow_recovery(
        flow_id,
        _email_browser_cookie(request),
        request.headers.get("x-csrf-token"),
        config=settings,
    )
    if recovery is None or not _headless_origin_matches(request, recovery["redirect_uri"]):
        return None
    if await _resolve_authorize_app(recovery["client_id"], recovery["redirect_uri"], db) is None:
        return None
    return _headless_error(
        "interaction_expired",
        "email login flow expired, please sign in again",
        status_code=410,
        state=recovery.get("app_state"),
    )


@router.post("/email/headless/start")
async def start_email_headless(
    request: Request,
    payload: EmailHeadlessStartRequest,
    db: AsyncSession = Depends(get_db),
):
    if payload.response_type != "code":
        return _headless_error(
            "unsupported_response_type",
            "only response_type=code is supported",
            status_code=400,
        )
    valid_state = _HEADLESS_STATE.fullmatch(payload.state) is not None
    if (
        payload.code_challenge_method != "S256"
        or _HEADLESS_S256_CHALLENGE.fullmatch(payload.code_challenge) is None
        or not valid_state
    ):
        return _headless_error(
            "invalid_request",
            "PKCE S256 challenge and a 32+ character URL-safe state are required",
            status_code=400,
            state=payload.state if valid_state else None,
        )
    if not _headless_origin_matches(request, payload.redirect_uri):
        return _headless_error(
            "origin_not_allowed",
            "request origin is not allowed for this redirect_uri",
            status_code=403,
        )
    if not settings.email_headless_login_enabled or not email_sender.is_email_login_available(settings):
        return _headless_error(
            "delivery_unavailable",
            "headless email login is unavailable",
            status_code=503,
        )
    if await _resolve_authorize_app(payload.client_id, payload.redirect_uri, db) is None:
        return _headless_error(
            "invalid_client",
            "unknown client_id or unregistered redirect_uri",
            status_code=400,
        )

    allowed, retry_after = await email_login_service.acquire_email_flow_creation_slot(
        payload.client_id,
        _email_client_ip(request),
        config=settings,
    )
    if not allowed:
        return _headless_error(
            "rate_limited",
            "too many email login requests",
            status_code=429,
            retry_after=retry_after,
        )
    started = await email_login_service.create_email_flow(
        client_id=payload.client_id,
        redirect_uri=payload.redirect_uri,
        app_state=payload.state,
        code_challenge=payload.code_challenge,
        browser_cookie=request.cookies.get(email_login_service.email_browser_cookie_name(settings)),
        config=settings,
    )
    response = _headless_json(
        {
            "flow_id": started.flow_id,
            "csrf_token": started.csrf_token,
            "expires_in": settings.email_flow_ttl_seconds,
            "code_length": 6,
        },
        status_code=201,
    )
    response.set_cookie(
        key=started.cookie_name,
        value=started.cookie_value,
        max_age=settings.email_flow_recovery_ttl_seconds,
        path="/",
        domain=settings.session_cookie_domain,
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.post("/email/headless/send")
async def send_email_headless(
    request: Request,
    payload: EmailHeadlessSendRequest,
    db: AsyncSession = Depends(get_db),
    sender: EmailSender = Depends(get_email_sender),
):
    flow = await _validated_headless_email_flow(request, payload.flow_id)
    if flow is None:
        expired = await _expired_headless_email_flow_response(request, payload.flow_id, db)
        return expired or _headless_error(
            "invalid_interaction",
            "email login interaction is invalid",
            status_code=403,
        )
    if not settings.email_headless_login_enabled:
        return _headless_error(
            "delivery_unavailable",
            "headless email login is unavailable",
            status_code=503,
        )
    result = await email_login_service.request_login_code(
        flow_id=payload.flow_id,
        flow_cookie=_email_browser_cookie(request),
        email=str(payload.email),
        client_ip=_email_client_ip(request),
        db=db,
        sender=sender,
        defer_delivery=True,
        config=settings,
    )
    if result.unavailable:
        return _headless_error(
            "delivery_unavailable",
            "email delivery is unavailable",
            status_code=503,
        )
    if not result.accepted:
        return _headless_error(
            "rate_limited",
            "too many verification code requests",
            status_code=429,
            retry_after=result.retry_after,
        )
    background = None
    if result.delivery is not None:
        background = BackgroundTask(email_login_service.complete_login_code_delivery, result.delivery, sender)
    return _headless_json(
        {
            "accepted": True,
            "next": "verify",
            "expires_in": settings.email_code_ttl_seconds,
            "resend_after": settings.email_code_resend_seconds,
            "masked_destination": email_login_service.mask_email(str(payload.email)),
        },
        status_code=202,
        background=background,
    )


@router.post("/email/headless/verify")
async def verify_email_headless(
    request: Request,
    payload: EmailHeadlessVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    flow = await _validated_headless_email_flow(request, payload.flow_id)
    if flow is None:
        expired = await _expired_headless_email_flow_response(request, payload.flow_id, db)
        return expired or _headless_error(
            "invalid_interaction",
            "email login interaction is invalid",
            status_code=403,
        )
    if not settings.email_headless_login_enabled or not settings.email_login_enabled:
        return _headless_error(
            "delivery_unavailable",
            "headless email login is unavailable",
            status_code=503,
        )
    if await _resolve_authorize_app(flow["client_id"], flow["redirect_uri"], db) is None:
        return _headless_error(
            "invalid_client",
            "application login configuration changed",
            status_code=400,
        )
    verified = await email_login_service.verify_login_code(
        flow_id=payload.flow_id,
        flow_cookie=_email_browser_cookie(request),
        code=payload.code,
        db=db,
        config=settings,
    )
    if verified is None:
        return _headless_error(
            "invalid_code",
            "verification code is invalid or expired",
            status_code=400,
        )

    flow = verified.flow
    auth_code = await oauth_service.mint_auth_code(
        user_id=str(verified.user.id),
        client_id=flow["client_id"],
        redirect_uri=flow["redirect_uri"],
        provider="email_otp",
        code_challenge=flow["code_challenge"],
    )
    response = _headless_json(
        {
            "code": auth_code,
            "state": flow["app_state"],
            "expires_in": settings.auth_code_expire_seconds,
        }
    )
    await session_service.start_session(response, str(verified.user.id), ["email_otp"])
    return response


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
    db: AsyncSession = Depends(get_db),
):
    """Single Logout: destroy the IdP session, revoke all refresh tokens, clear the cookie.

    POST-only (never GET) so it cannot be triggered by a cross-site <img>/navigation.
    ``post_logout_redirect_uri`` and ``client_id`` may be sent as a JSON body OR as
    urlencoded form fields -- the form variant lets a top-level ``<form method=POST>``
    deliver them so the SameSite=Lax session cookie rides the navigation to this
    cross-site, POST-only endpoint. For true "logout everywhere", in-flight stateless
    access tokens are also killed via a per-user revocation marker (see
    ``revoke_user_access_tokens``), which resource servers check on the next request --
    so a token already held by another app stops working without waiting out its TTL.
    """
    post_logout_redirect_uri, client_id = await _read_logout_params(request)

    sid = session_service.read_sid(request)
    session = await get_session(sid) if sid else None
    if session:
        user_id = session.get("user_id")
        if user_id:
            await auth_service._revoke_all_user_tokens(uuid.UUID(user_id), db)
            # Also kill in-flight stateless access tokens for this user: revoking refresh
            # tokens only stops NEW ones, but the user's other apps still hold valid access
            # tokens until they expire. TTL = access-token lifetime so the marker self-cleans.
            # Best-effort: this marker is an optimization on top of refresh-token revocation,
            # so a shared-Redis blip must not break logout itself (cookie + session below must
            # still clear). Degraded mode: those access tokens then live out their <=15-min TTL.
            try:
                await revoke_user_access_tokens(user_id, time.time(), settings.access_token_expire_minutes * 60 + 60)
            except Exception:
                logger.warning("failed to write access-token revocation marker on logout", exc_info=True)
    if sid:
        await delete_session(sid)

    if post_logout_redirect_uri and await _is_registered_redirect(post_logout_redirect_uri, db, client_id):
        redirect = RedirectResponse(url=post_logout_redirect_uri, status_code=302)
        session_service.clear_session_cookie(redirect)
        return redirect

    session_service.clear_session_cookie(response)
    return MessageResponse(message="Logged out")


async def _read_logout_params(request: Request) -> tuple[str | None, str | None]:
    """Pull (post_logout_redirect_uri, client_id) from a JSON or urlencoded form body.

    A top-level ``<form method=POST>`` (urlencoded) is how the SameSite=Lax session cookie
    reaches this POST-only endpoint cross-site; JSON is kept for programmatic callers.
    Parsed manually (no Pydantic body model / no ``Form(...)``) so a single endpoint can
    accept either content type without FastAPI body-media ambiguity.
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            data = json.loads(await request.body() or b"null")
        except (ValueError, TypeError):
            return None, None
        if not isinstance(data, dict):
            return None, None
    elif "application/x-www-form-urlencoded" in content_type:
        parsed = parse_qs((await request.body()).decode("utf-8", "ignore"))
        data = {key: values[0] for key, values in parsed.items() if values}
    else:
        return None, None
    return data.get("post_logout_redirect_uri"), data.get("client_id")


async def _is_registered_redirect(uri: str, db: AsyncSession, client_id: str | None = None) -> bool:
    """True if uri is a registered redirect_uri (open-redirect guard).

    When ``client_id`` is supplied, the uri must be registered for THAT app (tighter, so a
    uri registered for app B is not accepted when app A logs out); otherwise it may match
    any active app (back-compat for clientless callers).
    """
    if not oauth_redirect_uri_allowed(uri):
        return False
    if client_id:
        return await _resolve_authorize_app(client_id, uri, db) is not None
    result = await db.execute(select(Application).where(Application.is_active.is_(True)))
    return any(uri in app.redirect_uris for app in result.scalars())


async def _resolve_authorize_app(client_id: str, redirect_uri: str, db: AsyncSession) -> Application | None:
    """Return the active Application iff redirect_uri is an exact registered match, else None."""
    if not oauth_redirect_uri_allowed(redirect_uri):
        return None
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
        return oauth_redirect(redirect_uri, params)

    # 5. interaction required
    if prompt == "none":
        return oauth_error("login_required", "no active session", redirect_uri, state)

    if provider not in ("google", "github"):
        # 交互式授权仅支持已托管回调的社交提供方；邮箱验证码走 headless JSON 协议。
        return oauth_error("invalid_request", "provider must be google or github", redirect_uri, state)

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
