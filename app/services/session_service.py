"""IdP session layer: secret cookie key <-> Redis-backed SSO session.

The browser cookie contains a secret ``cookie_sid`` that is used only as the Redis
lookup key.  Tokens carry a different, public ``session_id`` from the stored payload.
Keeping those values independent is critical: JWT payloads and URL tickets are readable
by clients and must never reveal a value that can be replayed as the HttpOnly cookie.
"""

import secrets
import time
from dataclasses import dataclass

from fastapi import Request, Response

from app.config import get_settings
from app.security.revocation import is_sid_revoked
from app.utils.redis import create_session as store_session
from app.utils.redis import delete_session, get_session, touch_session

settings = get_settings()


@dataclass(frozen=True)
class CreatedSession:
    """Identifiers for a newly-created central session.

    ``cookie_sid`` is secret and must only be written to the cookie/Redis key.
    ``session_id`` is public and is the only identifier allowed in tokens and
    revocation markers.
    """

    cookie_sid: str
    session_id: str
    version: str


def set_session_cookie(response: Response, cookie_sid: str) -> None:
    """Write the session cookie. HttpOnly always; Secure + __Host- in production."""
    response.set_cookie(
        key=settings.session_cookie_name,
        value=cookie_sid,
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
    """Return (cookie_sid, payload) for a valid live session, else (None, None).

    Enforces the absolute-lifetime cap (purging the session if exceeded) and
    slides the TTL forward on every valid hit.
    """
    cookie_sid = read_sid(request)
    if not cookie_sid:
        return None, None
    payload = await resolve_cookie_sid(cookie_sid)
    return (cookie_sid, payload) if payload is not None else (None, None)


async def resolve_cookie_sid(cookie_sid: str) -> dict | None:
    """按 secret lookup key 复验并续期中央会话，不依赖当前请求 Cookie。

    仅供 auth-service 内部的一次性 code 绑定复验；调用方不得把 ``cookie_sid``
    返回到 JSON、URL 或日志。
    """
    payload = await get_session(cookie_sid)
    if payload is None:
        return None
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        await delete_session(cookie_sid)
        return None
    if await is_sid_revoked(session_id):
        await delete_session(cookie_sid)
        return None
    auth_time = int(payload.get("auth_time", 0))
    if int(time.time()) - auth_time > settings.session_absolute_max_seconds:
        await delete_session(cookie_sid)
        return None
    await touch_session(cookie_sid, settings.session_ttl_seconds)
    return payload


async def create_session(
    user_id: str,
    amr: list[str],
    auth_generation: int = 0,
    previous_sid: str | None = None,
) -> CreatedSession:
    """创建全新 IdP session，但不提前撤销旧 token 会话族。

    ``previous_sid`` 仅为兼容签名保留；本函数不触碰旧会话。调用方必须先成功
    持久化继任 auth code，再删除旧中央 Cookie session；旧 token 的公开 session_id
    则在继任 token 成功签发后撤销，避免换票失败造成不可恢复登出。
    """
    cookie_sid = secrets.token_urlsafe(32)
    session_id = secrets.token_urlsafe(24)
    version = secrets.token_urlsafe(16)
    now = int(time.time())
    await store_session(
        cookie_sid,
        {
            "session_id": session_id,
            "user_id": user_id,
            "auth_generation": auth_generation,
            "auth_time": now,
            "amr": amr,
            "created_at": now,
            "last_seen": now,
            # 独立随机版本用于 reconcile 换票时复验，避免 sid 对应 payload 被替换。
            "version": version,
        },
        settings.session_ttl_seconds,
    )
    return CreatedSession(cookie_sid=cookie_sid, session_id=session_id, version=version)


async def start_session(
    response: Response,
    user_id: str,
    amr: list[str],
    auth_generation: int = 0,
    previous_sid: str | None = None,
) -> str:
    """兼容入口：创建 session，写入并返回 secret cookie lookup key。

    业务签发路径应直接使用 ``create_session()`` 的 ``session_id``；本函数仅保留
    既有 session 层调用约定，返回值不得写进 JWT 或 URL。
    """
    created = await create_session(user_id, amr, auth_generation, previous_sid)
    if previous_sid:
        await delete_session(previous_sid)
    set_session_cookie(response, created.cookie_sid)
    return created.cookie_sid
