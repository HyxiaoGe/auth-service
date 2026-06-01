"""IdP session layer: cookie <-> Redis-backed session, for SSO.

The session cookie holds only an opaque ``sid``; all real state lives in Redis
(``sso_session:<sid>``). This is the IdP-side session that makes cross-app SSO
possible: every app navigates here, and a live session yields silent auth.
"""

import secrets
import time

from fastapi import Request, Response

from app.config import get_settings
from app.utils.redis import create_session, delete_session, get_session, touch_session

settings = get_settings()


def set_session_cookie(response: Response, sid: str) -> None:
    """Write the session cookie. HttpOnly always; Secure + __Host- in production."""
    response.set_cookie(
        key=settings.session_cookie_name,
        value=sid,
        max_age=settings.session_ttl_seconds,
        path="/",
        domain=settings.session_cookie_domain,
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite=settings.session_cookie_samesite,
    )


def clear_session_cookie(response: Response) -> None:
    """Expire the session cookie (Max-Age=0)."""
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        domain=settings.session_cookie_domain,
    )


def read_sid(request: Request) -> str | None:
    return request.cookies.get(settings.session_cookie_name)


async def resolve_session(request: Request) -> tuple[str | None, dict | None]:
    """Return (sid, payload) for a valid live session, else (None, None).

    Enforces the absolute-lifetime cap (purging the session if exceeded) and
    slides the TTL forward on every valid hit.
    """
    sid = read_sid(request)
    if not sid:
        return None, None
    payload = await get_session(sid)
    if payload is None:
        return None, None
    auth_time = int(payload.get("auth_time", 0))
    if int(time.time()) - auth_time > settings.session_absolute_max_seconds:
        await delete_session(sid)
        return None, None
    await touch_session(sid, settings.session_ttl_seconds)
    return sid, payload


async def start_session(response: Response, user_id: str, amr: list[str]) -> str:
    """Mint a brand-new session (fresh sid -> Redis -> Set-Cookie) and return the sid.

    A fresh sid is generated on every call and the inbound cookie is never reused,
    which is the anti session-fixation guarantee.
    """
    sid = secrets.token_urlsafe(32)
    now = int(time.time())
    await create_session(
        sid,
        {"user_id": user_id, "auth_time": now, "amr": amr, "created_at": now, "last_seen": now},
        settings.session_ttl_seconds,
    )
    set_session_cookie(response, sid)
    return sid
