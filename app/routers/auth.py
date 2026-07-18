import json
import logging
import time
import uuid
from html import escape
from ipaddress import ip_address
from typing import Annotated
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from app.config import get_settings
from app.database import get_db
from app.models import Application, User, UserPreference
from app.schemas import (
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
from app.utils.redis import delete_session, get_session

router = APIRouter(prefix="/auth", tags=["Authentication"])

logger = logging.getLogger(__name__)

settings = get_settings()


@router.get("/capabilities")
async def capabilities():
    """公开返回可安全展示的认证能力，不暴露 SMTP 等内部配置。"""
    return JSONResponse(
        content={"email_login": email_sender.is_email_login_available(settings)},
        headers={"Cache-Control": "no-store"},
    )


def _form_action_source(redirect_uri: str | None) -> str | None:
    if not redirect_uri:
        return None
    parsed = urlsplit(redirect_uri)
    if parsed.scheme not in {"https", "http", "app"} or not parsed.netloc:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if any(char in parsed.netloc for char in "'\"; \t\r\n"):
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _secure_html(response: HTMLResponse, *, form_redirect_uri: str | None = None) -> HTMLResponse:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # 表单 POST 需要携带真实 Origin 做 CSRF 防护；Fetch 规范会在 no-referrer 下把
    # 非 CORS POST 的 Origin 降为 null。origin 仅发送源，不泄露 /authorize 查询参数。
    response.headers["Referrer-Policy"] = "origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    form_actions = "'self'"
    if redirect_source := _form_action_source(form_redirect_uri):
        # Chrome 会把表单提交后的 302 继续视为 form-action；只放行已注册回调的源，
        # 不携带路径或查询参数，也不放宽到任意 HTTPS 站点。
        form_actions = f"{form_actions} {redirect_source}"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        f"form-action {form_actions}; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


def _email_login_page(
    flow_id: str,
    *,
    csrf_token: str = "",
    form_redirect_uri: str | None = None,
    code_requested: bool = False,
    message: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    safe_flow_id = escape(flow_id, quote=True)
    safe_csrf_token = escape(csrf_token, quote=True)
    notice = f'<p class="notice">{escape(message)}</p>' if message else ""
    if code_requested:
        form = f"""
        <form method="post" action="/auth/email/verify">
          <input type="hidden" name="flow_id" value="{safe_flow_id}">
          <input type="hidden" name="csrf_token" value="{safe_csrf_token}">
          <label for="code">邮箱验证码</label>
          <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" maxlength="6" required>
          <button type="submit">验证并登录</button>
        </form>
        <form method="post" action="/auth/email/send" class="secondary">
          <input type="hidden" name="flow_id" value="{safe_flow_id}">
          <input type="hidden" name="csrf_token" value="{safe_csrf_token}">
          <label for="email">重新发送到邮箱</label>
          <input id="email" name="email" type="email" autocomplete="email" required>
          <button type="submit">重新发送</button>
        </form>"""
    else:
        form = f"""
        <form method="post" action="/auth/email/send">
          <input type="hidden" name="flow_id" value="{safe_flow_id}">
          <input type="hidden" name="csrf_token" value="{safe_csrf_token}">
          <label for="email">邮箱</label>
          <input id="email" name="email" type="email" autocomplete="email" required autofocus>
          <button type="submit">发送验证码</button>
        </form>"""
    html = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>邮箱验证码登录</title><style>
body{{font-family:system-ui,sans-serif;background:#f6f7f9;color:#18202a;margin:0;min-height:100vh;display:grid;place-items:center}}
main{{width:min(420px,calc(100% - 32px));background:#fff;padding:32px;border-radius:16px;box-shadow:0 8px 30px #00000014}}
h1{{font-size:22px;margin:0 0 8px}}p{{color:#59636e;line-height:1.6}}form{{display:grid;gap:12px;margin-top:24px}}
label{{font-weight:600}}input{{font:inherit;padding:12px;border:1px solid #c7cdd4;border-radius:10px}}
button{{font:inherit;font-weight:650;padding:12px;border:0;border-radius:10px;background:#111827;color:white;cursor:pointer}}
.notice{{background:#f0f7ff;color:#174f82;padding:10px 12px;border-radius:10px}}.secondary{{border-top:1px solid #e5e7eb;padding-top:20px}}
</style></head><body><main><h1>邮箱验证码登录</h1><p>验证码仅用于本次安全登录。</p>{notice}{form}</main></body></html>"""
    return _secure_html(HTMLResponse(html, status_code=status_code), form_redirect_uri=form_redirect_uri)


def _email_unavailable_page(*, form_redirect_uri: str | None = None) -> HTMLResponse:
    return _email_login_page(
        "",
        form_redirect_uri=form_redirect_uri,
        message="邮箱登录暂不可用，请稍后再试。",
        status_code=503,
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


def _trusted_email_origin(request: Request) -> bool:
    expected = urlsplit(settings.auth_base_url)
    return request.headers.get("origin") == f"{expected.scheme}://{expected.netloc}"


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


async def _validated_email_flow(request: Request, flow_id: str, csrf_token: str) -> dict | None:
    if not _trusted_email_origin(request):
        logger.warning("email_login.flow_validation_failed reason=origin_mismatch")
        return None
    browser_cookie = _email_browser_cookie(request)
    if not browser_cookie:
        logger.warning("email_login.flow_validation_failed reason=browser_cookie_missing")
        return None
    flow = await email_login_service.get_bound_email_flow(
        flow_id,
        browser_cookie,
        config=settings,
    )
    if flow is None:
        logger.warning("email_login.flow_validation_failed reason=flow_binding_mismatch")
        return None
    if not email_login_service.email_flow_csrf_matches(flow, csrf_token, settings):
        logger.warning("email_login.flow_validation_failed reason=csrf_mismatch")
        return None
    return flow


async def _expired_email_flow_redirect(
    request: Request,
    flow_id: str,
    csrf_token: str,
    db: AsyncSession,
) -> RedirectResponse | None:
    if not _trusted_email_origin(request):
        return None
    recovery = await email_login_service.get_bound_email_flow_recovery(
        flow_id,
        _email_browser_cookie(request),
        csrf_token,
        config=settings,
    )
    if recovery is None:
        return None
    if await _resolve_authorize_app(recovery["client_id"], recovery["redirect_uri"], db) is None:
        return None
    return oauth_error(
        "login_required",
        "email login flow expired, please sign in again",
        recovery["redirect_uri"],
        recovery.get("app_state"),
    )


@router.post("/email/send", response_class=HTMLResponse)
async def send_email_code(
    request: Request,
    flow_id: Annotated[str, Form(min_length=16, max_length=128)],
    csrf_token: Annotated[str, Form(min_length=32, max_length=128)],
    email: Annotated[EmailStr, Form()],
    db: AsyncSession = Depends(get_db),
    sender: EmailSender = Depends(get_email_sender),
):
    flow = await _validated_email_flow(request, flow_id, csrf_token)
    if flow is None:
        expired = await _expired_email_flow_redirect(request, flow_id, csrf_token, db)
        return expired or _email_login_page(flow_id, status_code=403, message="登录请求无效，请重新开始。")
    result = await email_login_service.request_login_code(
        flow_id=flow_id,
        flow_cookie=_email_browser_cookie(request),
        email=str(email),
        client_ip=_email_client_ip(request),
        db=db,
        sender=sender,
        defer_delivery=True,
        config=settings,
    )
    if result.unavailable:
        return _email_unavailable_page(form_redirect_uri=flow["redirect_uri"])
    if not result.accepted:
        response = _email_login_page(
            flow_id,
            csrf_token=csrf_token,
            form_redirect_uri=flow["redirect_uri"],
            message="请求过于频繁，请稍后再试。",
            status_code=429,
        )
        if result.retry_after:
            response.headers["Retry-After"] = str(result.retry_after)
        return response
    response = _email_login_page(
        flow_id,
        csrf_token=csrf_token,
        form_redirect_uri=flow["redirect_uri"],
        code_requested=True,
        message="如果该邮箱已关联有效账号，验证码已经发送。",
    )
    if result.delivery is not None:
        response.background = BackgroundTask(
            email_login_service.complete_login_code_delivery,
            result.delivery,
            sender,
        )
    return response


@router.post("/email/verify")
async def verify_email_code(
    request: Request,
    flow_id: Annotated[str, Form(min_length=16, max_length=128)],
    csrf_token: Annotated[str, Form(min_length=32, max_length=128)],
    code: Annotated[str, Form(pattern=r"^[0-9]{6}$")],
    db: AsyncSession = Depends(get_db),
):
    if not settings.email_login_enabled:
        return _email_unavailable_page()
    flow = await _validated_email_flow(request, flow_id, csrf_token)
    if flow is None:
        expired = await _expired_email_flow_redirect(request, flow_id, csrf_token, db)
        return expired or _email_login_page(flow_id, status_code=403, message="登录请求无效，请重新开始。")
    if await _resolve_authorize_app(flow["client_id"], flow["redirect_uri"], db) is None:
        return _email_login_page(
            flow_id,
            form_redirect_uri=flow["redirect_uri"],
            status_code=400,
            message="应用登录配置已变更，请返回应用后重新开始。",
        )
    verified = await email_login_service.verify_login_code(
        flow_id=flow_id,
        flow_cookie=_email_browser_cookie(request),
        code=code,
        db=db,
        config=settings,
    )
    if verified is None:
        return _email_login_page(
            flow_id,
            csrf_token=csrf_token,
            form_redirect_uri=flow["redirect_uri"],
            code_requested=True,
            message="验证码无效或已过期。",
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
    params = {"code": auth_code}
    if flow.get("app_state") is not None:
        params["state"] = flow["app_state"]
    response = oauth_redirect(flow["redirect_uri"], params)
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
    if client_id:
        return await _resolve_authorize_app(client_id, uri, db) is not None
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
        return oauth_redirect(redirect_uri, params)

    # 5. interaction required
    if prompt == "none":
        return oauth_error("login_required", "no active session", redirect_uri, state)

    if provider not in ("google", "github", "email"):
        # MVP: the app's SDK renders its own provider buttons, so a no-provider interactive
        # hit is bounced back for the app to handle (a hosted chooser page is deferred).
        return oauth_error("invalid_request", "provider is required", redirect_uri, state)

    if provider == "email":
        if not email_sender.is_email_login_available(settings):
            return _email_unavailable_page()
        allowed, retry_after = await email_login_service.acquire_email_flow_creation_slot(
            client_id,
            _email_client_ip(request),
            config=settings,
        )
        if not allowed:
            response = _email_login_page(
                "",
                form_redirect_uri=redirect_uri,
                message="请求过于频繁，请稍后再试。",
                status_code=429,
            )
            response.headers["Retry-After"] = str(retry_after)
            return response
        started = await email_login_service.create_email_flow(
            client_id=client_id,
            redirect_uri=redirect_uri,
            app_state=state,
            code_challenge=code_challenge,
            browser_cookie=request.cookies.get(email_login_service.email_browser_cookie_name(settings)),
            config=settings,
        )
        response = _email_login_page(
            started.flow_id,
            csrf_token=started.csrf_token,
            form_redirect_uri=redirect_uri,
        )
        response.set_cookie(
            key=started.cookie_name,
            value=started.cookie_value,
            max_age=settings.email_flow_recovery_ttl_seconds,
            path="/",
            domain=settings.session_cookie_domain,
            secure=settings.session_cookie_secure,
            httponly=True,
            # 跨站顶层 GET /authorize 必须携带稳定浏览器绑定；POST 仍由 Origin + CSRF 防护。
            samesite="lax",
        )
        return response

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
