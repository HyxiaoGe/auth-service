"""集中式邮箱验证码登录业务逻辑。"""

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass, field
from time import time as current_timestamp

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.models import User
from app.services.email_sender import EmailDeliveryError, EmailSender
from app.services.identity_service import (
    InactiveIdentityError,
    find_active_user_by_id,
    find_user_by_email,
    get_or_create_active_user,
)
from app.utils import redis as redis_util
from app.utils.email import normalize_email
from app.utils.redis import (
    acquire_email_authorize_slot,
    acquire_email_send_slot,
    acquire_email_verify_flow_slot,
    acquire_email_verify_request_slot,
    consume_email_otp,
    delete_email_flow,
    get_email_flow,
    get_email_flow_recovery,
    promote_email_otp,
    register_email_flow_for_browser,
    stage_email_otp,
    store_email_flow,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmailFlowStart:
    flow_id: str
    cookie_name: str
    cookie_value: str
    csrf_token: str


@dataclass(frozen=True)
class CodeRequestResult:
    accepted: bool
    retry_after: int = 0
    unavailable: bool = False
    delivery: "EmailCodeDelivery | None" = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class EmailCodeDelivery:
    flow_id: str
    recipient: str | None
    code: str
    code_mac: str
    ttl_seconds: int


@dataclass(frozen=True)
class EmailVerification:
    user: User
    flow: dict


def mask_email(email: str) -> str:
    """仅保留本地部分首字符和域名，用于回显用户刚提交的目标。"""
    local, domain = normalize_email(email).rsplit("@", 1)
    return f"{local[:1]}***@{domain}"


def _mac(value: str, config: Settings) -> str:
    return hmac.new(config.email_code_pepper.encode(), value.encode(), hashlib.sha256).hexdigest()


def email_browser_cookie_name(config: Settings) -> str:
    return (
        "__Host-email_browser"
        if config.session_cookie_secure and config.session_cookie_domain is None
        else "email_browser"
    )


async def acquire_email_flow_creation_slot(
    client_id: str,
    client_ip: str,
    *,
    config: Settings | None = None,
) -> tuple[bool, int]:
    config = config or get_settings()
    return await acquire_email_authorize_slot(
        _mac(f"client:{client_id}", config),
        _mac(f"ip:{client_ip}", config),
        window_seconds=config.email_rate_limit_window_seconds,
        client_limit=config.email_authorize_rate_limit_per_client,
        ip_limit=config.email_authorize_rate_limit_per_ip,
        global_limit=config.email_authorize_rate_limit_global,
    )


async def acquire_email_verification_request_slot(
    client_ip: str,
    *,
    config: Settings | None = None,
) -> tuple[bool, int]:
    config = config or get_settings()
    return await acquire_email_verify_request_slot(
        _mac(f"ip:{client_ip}", config),
        window_seconds=config.email_rate_limit_window_seconds,
        ip_limit=config.email_verify_rate_limit_per_ip,
        global_limit=config.email_verify_rate_limit_global,
    )


async def acquire_email_send_request_slot(
    client_ip: str,
    *,
    config: Settings | None = None,
) -> tuple[bool, int]:
    config = config or get_settings()
    return await redis_util.acquire_email_send_request_slot(
        _mac(f"ip:{client_ip}", config),
        window_seconds=config.email_rate_limit_window_seconds,
        ip_limit=config.email_send_request_rate_limit_per_ip,
        global_limit=config.email_send_request_rate_limit_global,
    )


async def acquire_email_send_request_flow_slot(
    flow_id: str,
    *,
    config: Settings | None = None,
) -> tuple[bool, int]:
    config = config or get_settings()
    return await redis_util.acquire_email_send_request_flow_slot(
        flow_id,
        window_seconds=config.email_rate_limit_window_seconds,
        flow_limit=config.email_send_request_rate_limit_per_flow,
    )


async def acquire_email_verification_flow_slot(
    flow_id: str,
    *,
    config: Settings | None = None,
) -> tuple[bool, int]:
    config = config or get_settings()
    return await acquire_email_verify_flow_slot(
        flow_id,
        window_seconds=config.email_rate_limit_window_seconds,
        flow_limit=config.email_verify_rate_limit_per_flow,
    )


async def create_email_flow(
    *,
    client_id: str,
    redirect_uri: str,
    app_state: str | None,
    code_challenge: str,
    browser_cookie: str | None = None,
    config: Settings | None = None,
) -> EmailFlowStart:
    config = config or get_settings()
    flow_id = secrets.token_urlsafe(24)
    browser_token = browser_cookie if browser_cookie and 32 <= len(browser_cookie) <= 256 else secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    payload = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "nonce_mac": _mac(browser_token, config),
        "csrf_mac": _mac(f"csrf:{csrf_token}", config),
    }
    if app_state is not None:
        payload["app_state"] = app_state
    await store_email_flow(
        flow_id,
        payload,
        config.email_flow_ttl_seconds,
        config.email_flow_recovery_ttl_seconds,
    )
    await register_email_flow_for_browser(
        _mac(f"browser:{browser_token}", config),
        flow_id,
        max_flows=config.email_flow_max_per_browser,
        ttl=config.email_flow_recovery_ttl_seconds,
    )
    return EmailFlowStart(
        flow_id=flow_id,
        cookie_name=email_browser_cookie_name(config),
        cookie_value=browser_token,
        csrf_token=csrf_token,
    )


async def get_bound_email_flow(
    flow_id: str,
    flow_cookie: str | None,
    *,
    config: Settings | None = None,
) -> dict | None:
    config = config or get_settings()
    if not flow_cookie:
        return None
    flow = await get_email_flow(flow_id)
    if flow is None or not hmac.compare_digest(str(flow.get("nonce_mac", "")), _mac(flow_cookie, config)):
        return None
    return flow


def email_flow_csrf_matches(flow: dict, csrf_token: str | None, config: Settings) -> bool:
    if not csrf_token:
        return False
    return hmac.compare_digest(str(flow.get("csrf_mac", "")), _mac(f"csrf:{csrf_token}", config))


async def get_bound_email_flow_recovery(
    flow_id: str,
    flow_cookie: str | None,
    csrf_token: str | None,
    *,
    config: Settings | None = None,
) -> dict | None:
    config = config or get_settings()
    if not flow_cookie:
        return None
    recovery = await get_email_flow_recovery(flow_id)
    if recovery is None:
        return None
    if not hmac.compare_digest(str(recovery.get("nonce_mac", "")), _mac(flow_cookie, config)):
        return None
    if not email_flow_csrf_matches(recovery, csrf_token, config):
        return None
    return recovery


async def request_login_code(
    *,
    flow_id: str,
    flow_cookie: str | None,
    email: str,
    client_ip: str,
    db: AsyncSession,
    sender: EmailSender,
    defer_delivery: bool = False,
    config: Settings | None = None,
) -> CodeRequestResult:
    config = config or get_settings()
    if not config.email_login_ready or not sender.available:
        return CodeRequestResult(accepted=False, unavailable=True)
    if await get_bound_email_flow(flow_id, flow_cookie, config=config) is None:
        return CodeRequestResult(accepted=False)

    normalized = normalize_email(email)
    email_digest = _mac(f"email:{normalized}", config)
    ip_digest = _mac(f"ip:{client_ip}", config)
    allowed, retry_after = await acquire_email_send_slot(
        email_digest,
        ip_digest,
        flow_id,
        cooldown_seconds=config.email_code_resend_seconds,
        window_seconds=config.email_rate_limit_window_seconds,
        email_limit=config.email_rate_limit_per_email,
        ip_limit=config.email_rate_limit_per_ip,
        flow_limit=config.email_rate_limit_per_flow,
        global_limit=config.email_send_rate_limit_global,
    )
    if not allowed:
        return CodeRequestResult(accepted=False, retry_after=retry_after)

    user = await find_user_by_email(normalized, db)
    code = f"{secrets.randbelow(1_000_000):06d}"
    payload = {
        "code_mac": _mac(f"code:{flow_id}:{code}", config),
        "attempts": 0,
        "email_digest": email_digest,
        "expires_at": current_timestamp() + config.email_code_ttl_seconds,
    }
    if user is None:
        payload["normalized_email"] = normalized
    elif user.is_active:
        payload["user_id"] = str(user.id)
    await stage_email_otp(flow_id, payload, config.email_code_ttl_seconds)
    delivery = EmailCodeDelivery(
        flow_id=flow_id,
        recipient=(user.email if user and user.is_active else normalized if user is None else None),
        code=code,
        code_mac=payload["code_mac"],
        ttl_seconds=config.email_code_ttl_seconds,
    )
    if defer_delivery:
        return CodeRequestResult(accepted=True, delivery=delivery)
    await complete_login_code_delivery(delivery, sender)
    return CodeRequestResult(accepted=True)


async def complete_login_code_delivery(delivery: EmailCodeDelivery, sender: EmailSender) -> None:
    """响应发送后完成真实投递；失败时保留 active 与 pending 供不确定投递恢复。"""
    should_promote = True
    if delivery.recipient:
        try:
            await sender.send_login_code(delivery.recipient, delivery.code, delivery.ttl_seconds)
        except EmailDeliveryError:
            # 不记录可与 flow 关联的账号存在性或投递差异；SMTP 全局状态由独立探测恢复。
            should_promote = False
    if should_promote:
        try:
            await promote_email_otp(delivery.flow_id, delivery.code_mac)
        except Exception:
            # SMTP 成功后 Redis 瞬时异常时 pending 仍可验证；响应已发出，不能让后台异常反向破坏请求。
            logger.exception("email_login.promote_failed")
    logger.info("email_login.code_request_processed")


async def verify_login_code(
    *,
    flow_id: str,
    flow_cookie: str | None,
    code: str,
    db: AsyncSession,
    config: Settings | None = None,
) -> EmailVerification | None:
    config = config or get_settings()
    flow = await get_bound_email_flow(flow_id, flow_cookie, config=config)
    if flow is None or not code.isdigit() or len(code) != 6:
        return None
    payload = await consume_email_otp(
        flow_id,
        _mac(f"code:{flow_id}:{code}", config),
        config.email_code_max_attempts,
    )
    if payload is None:
        return None
    user = None
    if payload.get("user_id"):
        user = await find_active_user_by_id(payload["user_id"], db)
    elif payload.get("normalized_email"):
        try:
            user = await get_or_create_active_user(
                payload["normalized_email"],
                name=None,
                avatar_url=None,
                db=db,
            )
        except InactiveIdentityError:
            return None
    if user is None:
        return None
    await delete_email_flow(flow_id)
    return EmailVerification(user=user, flow=flow)
