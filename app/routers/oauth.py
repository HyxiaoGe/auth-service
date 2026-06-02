import logging
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Application, User
from app.schemas import OAuthTokenExchangeRequest, TokenResponse
from app.services import auth_service, oauth_service, session_service
from app.utils.redis import consume_auth_code

router = APIRouter(prefix="/auth/oauth", tags=["OAuth"])

logger = logging.getLogger(__name__)


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
    request: Request,
    code: str,
    state: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Google OAuth callback. Generates a one-time auth code and redirects to frontend."""
    if not state:
        logger.warning(
            "oauth_state.missing provider=google reason=absent client_ip=%s code=%s",
            _client_ip(request),
            bool(code),
        )
        return _state_error_page()

    try:
        state_data = await oauth_service.verify_and_consume_state(state)
    except ValueError:
        logger.warning(
            "oauth_state.missing provider=google reason=not_found state=%s client_ip=%s code=%s",
            state[:12],
            _client_ip(request),
            bool(code),
        )
        return _state_error_page()

    logger.info("oauth_state.consume provider=google state=%s ok", state[:12])
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
    request: Request,
    code: str,
    state: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """GitHub OAuth callback. Generates a one-time auth code and redirects to frontend."""
    if not state:
        logger.warning(
            "oauth_state.missing provider=github reason=absent client_ip=%s code=%s",
            _client_ip(request),
            bool(code),
        )
        return _state_error_page()

    try:
        state_data = await oauth_service.verify_and_consume_state(state)
    except ValueError:
        logger.warning(
            "oauth_state.missing provider=github reason=not_found state=%s client_ip=%s code=%s",
            state[:12],
            _client_ip(request),
            bool(code),
        )
        return _state_error_page()

    logger.info("oauth_state.consume provider=github state=%s ok", state[:12])
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


def _client_ip(request: Request) -> str:
    """Real client IP for logging. We sit behind nginx/cloudflared, so prefer the first
    X-Forwarded-For hop; fall back to the direct peer.

    XFF is attacker-controlled and this value lands in log lines, so the result is
    sanitized: take only the first physical line (a forged newline would otherwise split
    one record into two -- log injection) and drop control chars / cap length. A
    whitespace-only hop strips to empty and falls through to the peer rather than emitting
    a blank ``client_ip=`` (which would defeat the instrumentation)."""
    xff = request.headers.get("x-forwarded-for") if request is not None else None
    candidate = xff.split(",")[0].strip() if xff else ""
    if not candidate and request is not None and request.client:
        candidate = request.client.host
    if not candidate:
        return "unknown"
    candidate = candidate.splitlines()[0].strip()
    candidate = "".join(c for c in candidate if c.isprintable())
    return candidate[:45] or "unknown"


def _state_error_page() -> HTMLResponse:
    """Branded 400 for a missing/expired ``oauth_state``.

    The Redis payload (client_id/redirect_uri) is gone together with the state, so we have
    no app to send the user back to -- a redirect here would risk a loop or an open
    redirect. We render a friendly, self-contained page instead of the raw JSON 400 that
    used to leave the user stranded on a looks-broken dead end. The accompanying
    ``oauth_state.missing`` log line is where the diagnosis lives.
    """
    html = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录会话已过期 · Session expired</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       background:#f6f7f9;color:#1f2328;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}
  .card{background:#fff;max-width:440px;width:90%;padding:40px 32px;border-radius:14px;
        box-shadow:0 1px 4px rgba(0,0,0,.08);text-align:center}
  h1{font-size:20px;margin:0 0 12px}
  p{font-size:14px;line-height:1.6;color:#57606a;margin:8px 0}
  .hint{font-size:12.5px;color:#8b949e;margin-top:20px}
</style>
</head>
<body>
  <div class="card">
    <h1>登录会话已过期</h1>
    <p>你的登录会话已失效或已超时（通常因为停留过久或网络较慢）。请<strong>返回应用并重新登录</strong>，不要刷新本页。</p>
    <p>Your sign-in session has expired or is invalid. Please return to the app and sign in again.</p>
    <p class="hint">如果反复出现，请稍后再试。</p>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=400)


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
