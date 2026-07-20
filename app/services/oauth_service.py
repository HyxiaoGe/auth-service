import hmac
import json
import logging
import secrets

from authlib.oauth2.rfc7636 import create_s256_code_challenge

from app.config import get_settings
from app.services.oauth_clients import create_github_client, create_google_client
from app.utils.email import normalize_email
from app.utils.redis import get_redis, store_auth_code

settings = get_settings()

logger = logging.getLogger(__name__)

OAUTH_STATE_PREFIX = "oauth_state:"
OAUTH_STATE_TTL = 300  # 5 minutes

# Durable, read-only recovery copy of a state's routing (client_id + redirect_uri only).
# The main oauth_state above is single-use (getdel) and short-lived, so its loss -- a slow
# round-trip past TTL, or a duplicate callback that already consumed it -- takes the only
# record of WHERE to return the user with it. This second copy decouples routing-lifetime
# from the single-use CSRF state so a lost state can bounce back to the app instead of
# dead-ending on the branded page. Longer TTL (covers a user dawdling on Google's consent
# screen) and never consumed (so duplicate callbacks both recover). Carries no secret.
OAUTH_STATE_RECOVER_PREFIX = "oauth_state_recover:"
OAUTH_STATE_RECOVER_TTL = 3600  # 1 hour


# ==================== One-time auth code ====================


async def mint_auth_code(
    user_id: str,
    client_id: str,
    redirect_uri: str,
    provider: str,
    auth_generation: int,
    code_challenge: str | None = None,
    sid: str | None = None,
    source_sid: str | None = None,
) -> str:
    """Create a one-time auth code (Redis, single-use) and return it.

    The single place auth codes are minted -- used by both the social callbacks and
    /authorize's silent path. When ``code_challenge`` is given it is bound into the
    payload so /token's conditional PKCE gate will demand a matching verifier; when None
    the key is omitted and the code behaves like a legacy code.
    """
    code = secrets.token_urlsafe(32)
    payload = {
        "user_id": user_id,
        "app_client_id": client_id,
        "redirect_uri": redirect_uri,
        "provider": provider,
        "auth_generation": auth_generation,
    }
    if code_challenge is not None:
        payload["code_challenge"] = code_challenge
    if sid is not None:
        payload["sid"] = sid
    if source_sid is not None and source_sid != sid:
        payload["source_sid"] = source_sid
    await store_auth_code(code, payload, settings.auth_code_expire_seconds)
    return code


async def mint_reconcile_auth_code(
    *,
    user_id: str,
    client_id: str,
    redirect_uri: str,
    auth_generation: int,
    code_challenge: str,
    sid: str,
    source_sid: str | None,
    session_version: str,
    origin: str,
    state: str,
) -> str:
    """签发只可在同一当前 IdP cookie 会话中兑换的账户切换授权码。"""
    code = secrets.token_urlsafe(32)
    payload = {
        "flow": "reconcile",
        "user_id": user_id,
        "app_client_id": client_id,
        "redirect_uri": redirect_uri,
        "provider": "sso_reconcile",
        "auth_generation": auth_generation,
        "code_challenge": code_challenge,
        "sid": sid,
        "source_sid": source_sid,
        "session_version": session_version,
        "origin": origin,
        "state": state,
    }
    await store_auth_code(code, payload, settings.auth_code_expire_seconds)
    return code


# ==================== PKCE (RFC 7636) ====================


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Return True iff BASE64URL(SHA256(code_verifier)) == code_challenge (S256 only).

    Public clients can't keep a client_secret, so this is what stops an intercepted
    auth code from being redeemed by anyone but the original requester. We only ever
    accept S256 (never ``plain``). The comparison is constant-time.
    """
    if not code_verifier or not code_challenge:
        return False
    # 由 Authlib 的 RFC 7636 实现生成标准 S256 challenge，避免在业务代码中
    # 将高熵 PKCE verifier 误建模成需要慢哈希保护的用户密码。
    expected = create_s256_code_challenge(code_verifier)
    return hmac.compare_digest(expected, code_challenge)


# ==================== State CSRF ====================


async def create_oauth_state(
    client_id: str,
    redirect_uri: str,
    *,
    app_state: str | None = None,
    prompt: str | None = None,
    provider: str | None = None,
    response_type: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    nonce: str | None = None,
) -> str:
    """Generate a random upstream state and stash the /authorize context behind it.

    The random ``state`` value is the only thing sent to Google/GitHub and is what the
    callback validates (upstream CSRF). Everything from /authorize -- including the app's
    own ``app_state`` -- rides along as Redis payload so the callback can resume the
    authorize flow and echo the app's state back. ``app_state`` is never a key and never
    leaves our server toward the IdP, keeping it cleanly separate from ``oauth_state``.
    Optional fields are omitted when None so the legacy payload stays byte-for-byte the
    same (zero-breakage).
    """
    payload = {"client_id": client_id, "redirect_uri": redirect_uri}
    extras = {
        "app_state": app_state,
        "prompt": prompt,
        "provider": provider,
        "response_type": response_type,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "nonce": nonce,
    }
    payload.update({k: v for k, v in extras.items() if v is not None})
    state = secrets.token_urlsafe(32)
    r = await get_redis()
    await r.setex(f"{OAUTH_STATE_PREFIX}{state}", OAUTH_STATE_TTL, json.dumps(payload))
    # Durable routing-only recovery copy (see OAUTH_STATE_RECOVER_PREFIX): outlives the
    # single-use main state so a lost/duplicate/slow callback can still bounce the user
    # back to the app instead of dead-ending. Only the public {client_id, redirect_uri}.
    await r.setex(
        f"{OAUTH_STATE_RECOVER_PREFIX}{state}",
        OAUTH_STATE_RECOVER_TTL,
        json.dumps({"client_id": client_id, "redirect_uri": redirect_uri}),
    )
    # Log only the first 12 chars (~72 bits) so create can be correlated with a later
    # consume/missing without ever putting the full single-use token in the logs.
    logger.info("oauth_state.create state=%s client_id=%s provider=%s", state[:12], client_id, provider)
    return state


async def verify_and_consume_state(state: str) -> dict:
    """Atomically read and delete state from Redis. Raises ValueError if invalid/expired."""
    r = await get_redis()
    raw = await r.getdel(f"{OAUTH_STATE_PREFIX}{state}")
    if raw is None:
        raise ValueError("Invalid or expired OAuth state")
    return json.loads(raw)


async def recover_state_routing(state: str) -> dict | None:
    """Read the durable recovery copy's routing for a consumed/expired state.

    Returns ``{client_id, redirect_uri}`` when the longer-lived recovery copy is still
    present, else ``None`` when truly unrecoverable -- a forged/garbage state (which never
    had a copy) or one past the recovery TTL. The None case is what keeps the branded page
    as a genuine last resort. Read-only (never deletes) so a duplicate callback recovers
    too. The recovery copy's existence is itself the "we minted this state" proof, so an
    attacker-supplied state cannot trigger a bounce.
    """
    r = await get_redis()
    raw = await r.get(f"{OAUTH_STATE_RECOVER_PREFIX}{state}")
    if raw is None:
        return None
    return json.loads(raw)


# ==================== Google ====================


def get_google_auth_url(state: str, prompt: str | None = None) -> str:
    """Generate Google OAuth authorization URL.

    ``prompt`` is driven by the caller (``/authorize``): the default sends no prompt so
    Google can silently reuse its own session (enabling SSO), while ``login`` /
    ``select_account`` force re-authentication. We no longer pin ``prompt=consent`` (it
    defeated SSO) nor request ``access_type=offline`` (we mint our own refresh tokens and
    never use Google's).
    """
    client = create_google_client()
    extra = {"prompt": prompt} if prompt else {}
    uri, _ = client.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        state=state,
        scope="openid email profile",
        **extra,
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
            "email": userinfo.get("email"),
            "email_verified": userinfo.get("verified_email") is True,
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

        email = await _get_github_primary_verified_email(client)

        return {
            "provider_id": str(user["id"]),
            "email": email,
            "email_verified": email is not None,
            "name": user.get("name") or user.get("login"),
            "avatar_url": user.get("avatar_url"),
        }


async def _get_github_primary_verified_email(client) -> str | None:
    """GitHub 邮箱是可降级属性；稳定 provider_id 仍可让已绑定身份登录。"""
    try:
        response = await client.get(
            "https://api.github.com/user/emails",
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        emails = response.json()
        if not isinstance(emails, list):
            raise ValueError("unexpected GitHub email response")
        for item in emails:
            if not isinstance(item, dict):
                raise ValueError("unexpected GitHub email item")
            if item.get("primary") is True and item.get("verified") is True:
                email = _canonical_github_email(item.get("email"))
                if email is not None:
                    return email
        return None
    except Exception:
        # 不记录上游响应或异常详情，避免令牌、邮箱或响应体泄露。
        logger.warning("github.user_emails_unavailable")
        return None


def _canonical_github_email(email: object) -> str | None:
    if not isinstance(email, str):
        return None
    try:
        canonical = normalize_email(email)
    except ValueError:
        return None
    domain = canonical.rpartition("@")[2]
    return None if domain.endswith("noreply.github.com") else canonical
