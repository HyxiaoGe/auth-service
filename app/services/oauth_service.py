import base64
import hashlib
import hmac
import json
import secrets

from app.config import get_settings
from app.services.oauth_clients import create_github_client, create_google_client
from app.utils.redis import get_redis, store_auth_code

settings = get_settings()

OAUTH_STATE_PREFIX = "oauth_state:"
OAUTH_STATE_TTL = 300  # 5 minutes


# ==================== One-time auth code ====================


async def mint_auth_code(
    user_id: str,
    client_id: str,
    redirect_uri: str,
    provider: str,
    code_challenge: str | None = None,
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
    }
    if code_challenge is not None:
        payload["code_challenge"] = code_challenge
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
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
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
    return state


async def verify_and_consume_state(state: str) -> dict:
    """Atomically read and delete state from Redis. Raises ValueError if invalid/expired."""
    r = await get_redis()
    raw = await r.getdel(f"{OAUTH_STATE_PREFIX}{state}")
    if raw is None:
        raise ValueError("Invalid or expired OAuth state")
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
            "email": userinfo["email"],
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

        email = user.get("email")
        if not email:
            email_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={"Accept": "application/json"},
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
