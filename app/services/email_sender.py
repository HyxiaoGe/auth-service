"""可注入的 SMTP / Resend 邮件发送适配器。"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import smtplib
import ssl
import time
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr
from html import escape
from pathlib import Path
from typing import Protocol

import httpx

from app.config import Settings, get_settings
from app.services import email_usage


class EmailDeliveryError(RuntimeError):
    def __init__(self, message: str, *, revokes_global_readiness: bool = True):
        super().__init__(message)
        self.revokes_global_readiness = revokes_global_readiness


class EmailSender(Protocol):
    available: bool

    async def send_login_code(
        self,
        recipient: str,
        code: str,
        ttl_seconds: int,
        delivery_id: str | None = None,
    ) -> None: ...

    async def preflight(self) -> None: ...


_smtp_verified = False
_smtp_failure_generation = 0
_smtp_probe_requested: asyncio.Event | None = None


def is_smtp_verified() -> bool:
    return _smtp_verified


async def wait_for_smtp_verification(timeout_seconds: float, *, poll_seconds: float = 0.05) -> bool:
    """限时等待后台 monitor 完成 SMTP acceptance 验证，不主动触发额外预检。"""
    if is_smtp_verified():
        return True
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, timeout_seconds)
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(poll_seconds, remaining))
        if is_smtp_verified():
            return True


def invalidate_smtp_verification() -> None:
    global _smtp_failure_generation, _smtp_verified
    _smtp_verified = False
    _smtp_failure_generation += 1
    if _smtp_probe_requested is not None:
        _smtp_probe_requested.set()


def smtp_failure_generation() -> int:
    return _smtp_failure_generation


def confirm_smtp_verification(generation: int) -> bool:
    """只允许未被更新失败事件淘汰的 acceptance preflight 重新开放能力。"""
    global _smtp_verified
    if generation != _smtp_failure_generation:
        return False
    _smtp_verified = True
    return True


def is_email_login_available(config: Settings) -> bool:
    return config.email_login_ready and is_smtp_verified()


class DisabledEmailSender:
    available = False

    async def send_login_code(
        self,
        recipient: str,
        code: str,
        ttl_seconds: int,
        delivery_id: str | None = None,
    ) -> None:
        raise EmailDeliveryError("email login is unavailable")

    async def preflight(self) -> None:
        raise EmailDeliveryError("email login is unavailable")


class SMTPEmailSender:
    available = True

    def __init__(self, config: Settings):
        self.config = config

    async def send_login_code(
        self,
        recipient: str,
        code: str,
        ttl_seconds: int,
        delivery_id: str | None = None,
    ) -> None:
        try:
            await asyncio.to_thread(self._send_sync, recipient, code, ttl_seconds)
        except smtplib.SMTPRecipientsRefused as exc:
            # 单个邮箱不存在、已满或策略拒收不代表 SMTP 连接、鉴权或发件人配置整体失效。
            raise EmailDeliveryError("SMTP delivery failed") from exc
        except Exception as exc:
            invalidate_smtp_verification()
            raise EmailDeliveryError("SMTP delivery failed") from exc

    async def preflight(self) -> None:
        """向专用地址提交部署预检邮件；只证明 SMTP 接受，不证明最终投递。"""
        try:
            await asyncio.to_thread(self._preflight_sync)
        except Exception as exc:
            raise EmailDeliveryError("SMTP preflight failed") from exc

    @contextmanager
    def _connection(self) -> Iterator[smtplib.SMTP]:
        tls_context = ssl.create_default_context()
        smtp_class = smtplib.SMTP_SSL if self.config.smtp_use_ssl else smtplib.SMTP
        smtp_kwargs = {"timeout": self.config.smtp_timeout_seconds}
        if self.config.smtp_use_ssl:
            smtp_kwargs["context"] = tls_context
        with smtp_class(self.config.smtp_host, self.config.smtp_port, **smtp_kwargs) as client:
            if self.config.smtp_starttls:
                client.starttls(context=tls_context)
            if self.config.smtp_username:
                client.login(self.config.smtp_username, self.config.smtp_password)
            yield client

    def _preflight_sync(self) -> None:
        message = self._message(
            recipient=self.config.smtp_smoke_recipient,
            subject="[部署预检] auth-service SMTP 接收验证",
            body=(
                "这是 auth-service 部署期间提交的 SMTP 接收级预检邮件，不包含登录验证码。\n\n"
                "SMTP 服务器接受该邮件不代表收件箱最终送达，也不代表 SPF、DKIM 或 DMARC 已通过。"
            ),
        )
        with self._connection() as client:
            client.send_message(message)

    def _message(
        self,
        *,
        recipient: str,
        subject: str,
        body: str,
        html_body: str | None = None,
    ) -> EmailMessage:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = formataddr((self.config.smtp_from_name, self.config.smtp_from_email))
        message["To"] = recipient
        message["Date"] = formatdate(localtime=False, usegmt=True)
        sender_domain = parseaddr(self.config.smtp_from_email)[1].rpartition("@")[2] or None
        message["Message-ID"] = make_msgid(domain=sender_domain)
        message["Auto-Submitted"] = "auto-generated"
        message.set_content(body)
        if html_body is not None:
            message.add_alternative(html_body, subtype="html")
        return message

    def _send_sync(self, recipient: str, code: str, ttl_seconds: int) -> None:
        minutes = max(1, ttl_seconds // 60)
        brand_name = self.config.smtp_from_name.strip() or self.config.smtp_from_email
        safe_brand_name = escape(brand_name)
        safe_code = escape(code)
        message = self._message(
            recipient=recipient,
            subject=f"{brand_name} 登录验证码",
            body=(
                f"你的 {brand_name} 登录验证码是：{code}\n\n"
                f"验证码将在 {minutes} 分钟后失效。若非本人操作，请忽略此邮件。"
            ),
            html_body=(
                '<!doctype html><html lang="zh-CN"><body>'
                f"<h1>{safe_brand_name} 登录验证码</h1>"
                "<p>请使用以下验证码完成登录：</p>"
                f'<p style="font-size:28px;font-weight:700;letter-spacing:6px">{safe_code}</p>'
                f"<p>验证码将在 {minutes} 分钟后失效。若非本人操作，请忽略此邮件。</p>"
                "</body></html>"
            ),
        )

        with self._connection() as client:
            client.send_message(message)


class ResendEmailSender:
    """使用 Resend Email API 的可选适配器，仅在显式配置 API key 时选用。"""

    available = True
    api_url = "https://api.resend.com/emails"

    def __init__(self, config: Settings):
        self.config = config
        self._preflight_idempotency_key: str | None = None

    def _idempotency_key(self, message_type: str, *parts: str) -> str:
        payload = "\0".join((message_type, *parts)).encode()
        digest = hmac.new(
            self.config.email_code_pepper.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()
        return f"auth-service-{message_type}-{digest}"

    def _preflight_cache_fingerprint(self) -> str:
        return self._idempotency_key(
            "preflight-cache",
            self.config.smtp_from_email.casefold(),
            self.config.smtp_smoke_recipient.casefold(),
            self.config.resend_api_key,
        )

    def _preflight_cache_valid(self) -> bool:
        if not self.config.resend_preflight_cache_path:
            return False
        try:
            cached = json.loads(Path(self.config.resend_preflight_cache_path).read_text())
            verified_at = cached["verified_at"]
            fingerprint = cached["fingerprint"]
            age = time.time() - float(verified_at)
            return (
                isinstance(fingerprint, str)
                and hmac.compare_digest(fingerprint, self._preflight_cache_fingerprint())
                and 0 <= age <= self.config.resend_preflight_cache_ttl_seconds
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return False

    def _record_preflight_cache(self) -> None:
        if not self.config.resend_preflight_cache_path:
            return
        path = Path(self.config.resend_preflight_cache_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "verified_at": time.time(),
                        "fingerprint": self._preflight_cache_fingerprint(),
                    },
                    separators=(",", ":"),
                )
            )
            path.chmod(0o600)
        except OSError:
            logging.getLogger(__name__).warning("resend.preflight_cache_write_failed")

    def _invalidate_preflight_cache(self) -> None:
        if not self.config.resend_preflight_cache_path:
            return
        try:
            Path(self.config.resend_preflight_cache_path).unlink(missing_ok=True)
        except OSError:
            logging.getLogger(__name__).warning("resend.preflight_cache_invalidate_failed")

    async def send_login_code(
        self,
        recipient: str,
        code: str,
        ttl_seconds: int,
        delivery_id: str | None = None,
    ) -> None:
        minutes = max(1, ttl_seconds // 60)
        brand_name = self.config.smtp_from_name.strip() or self.config.smtp_from_email
        safe_brand_name = escape(brand_name)
        safe_code = escape(code)
        idempotency_key = self._idempotency_key(
            "login-otp",
            delivery_id or "direct",
            recipient.casefold(),
            code,
        )
        try:
            await self._send(
                recipient=recipient,
                message_type="login_otp",
                idempotency_key=idempotency_key,
                subject=f"{brand_name} 登录验证码",
                text=(
                    f"你的 {brand_name} 登录验证码是：{code}\n\n"
                    f"验证码将在 {minutes} 分钟后失效。若非本人操作，请忽略此邮件。"
                ),
                html=(
                    '<!doctype html><html lang="zh-CN"><body>'
                    f"<h1>{safe_brand_name} 登录验证码</h1>"
                    "<p>请使用以下验证码完成登录：</p>"
                    f'<p style="font-size:28px;font-weight:700;letter-spacing:6px">{safe_code}</p>'
                    f"<p>验证码将在 {minutes} 分钟后失效。若非本人操作，请忽略此邮件。</p>"
                    "</body></html>"
                ),
            )
        except EmailDeliveryError as exc:
            # 收件人、请求参数和团队瞬时限流只影响本次请求；只有凭据、
            # 发件身份或 provider 级故障才撤销全局就绪并触发 monitor 预检。
            if exc.revokes_global_readiness:
                self._invalidate_preflight_cache()
                invalidate_smtp_verification()
            raise

    async def preflight(self) -> None:
        if self._preflight_cache_valid():
            return
        if self._preflight_idempotency_key is None:
            self._preflight_idempotency_key = f"auth-service-preflight-{secrets.token_hex(16)}"
        try:
            await self._send(
                recipient=self.config.smtp_smoke_recipient,
                message_type="preflight",
                idempotency_key=self._preflight_idempotency_key,
                subject="[部署预检] auth-service Resend 接收验证",
                text=(
                    "这是 auth-service 部署期间提交的 Resend API 接收级预检邮件，"
                    "不包含登录验证码。\n\n"
                    "Resend API 接受该邮件不代表收件箱最终送达。"
                ),
            )
        except EmailDeliveryError:
            raise EmailDeliveryError("Resend preflight failed") from None
        self._record_preflight_cache()
        self._preflight_idempotency_key = None

    async def _send(
        self,
        *,
        recipient: str,
        message_type: str,
        idempotency_key: str,
        subject: str,
        text: str,
        html: str | None = None,
    ) -> None:
        sender = formataddr((self.config.smtp_from_name, self.config.smtp_from_email))
        payload = {
            "from": sender,
            "to": [recipient],
            "subject": subject,
            "text": text,
            "headers": {"Auto-Submitted": "auto-generated"},
            "tags": [{"name": "message_type", "value": message_type}],
        }
        if html is not None:
            payload["html"] = html
        headers = {
            "Authorization": f"Bearer {self.config.resend_api_key}",
            "Idempotency-Key": idempotency_key,
            "User-Agent": f"{self.config.app_name}/1.0",
        }
        try:
            async with httpx.AsyncClient(timeout=self.config.resend_timeout_seconds) as client:
                response = await client.post(self.api_url, headers=headers, json=payload)
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            raise EmailDeliveryError(
                "Resend delivery failed",
                revokes_global_readiness=(
                    status_code in (401, 403) or status_code >= 500
                ),
            ) from None
        except Exception:
            raise EmailDeliveryError("Resend delivery failed") from None

        try:
            await email_usage.record_resend_usage(response.headers)
        except Exception:
            # 邮件已被上游接受；快照写入失败不得触发重发，也不记录响应内容。
            logging.getLogger(__name__).warning("resend.usage_snapshot_failed")


def _configured_email_sender(config: Settings) -> EmailSender:
    if config.resend_api_key:
        return ResendEmailSender(config)
    return SMTPEmailSender(config)


def get_email_sender() -> EmailSender:
    config = get_settings()
    if not is_email_login_available(config):
        return DisabledEmailSender()
    return _configured_email_sender(config)


async def monitor_smtp_verification(
    config: Settings,
    *,
    retry_seconds: float = 30.0,
    max_retry_seconds: float = 300.0,
) -> None:
    """启动和故障恢复均使用真实 acceptance 预检，成功后等待下一次失效信号。"""
    global _smtp_probe_requested
    sender = _configured_email_sender(config)
    probe_requested = asyncio.Event()
    _smtp_probe_requested = probe_requested
    retry_delay = retry_seconds
    try:
        while True:
            probe_requested.clear()
            generation = smtp_failure_generation()
            try:
                await sender.preflight()
            except EmailDeliveryError:
                invalidate_smtp_verification()
                await asyncio.sleep(retry_delay)
                retry_delay = min(max_retry_seconds, max(retry_seconds, retry_delay * 2))
                continue

            if not confirm_smtp_verification(generation):
                continue
            retry_delay = retry_seconds
            await probe_requested.wait()
    finally:
        if _smtp_probe_requested is probe_requested:
            _smtp_probe_requested = None
