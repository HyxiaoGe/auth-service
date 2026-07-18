"""可注入的 SMTP 邮件发送适配器。"""

import asyncio
import smtplib
import ssl
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import EmailMessage
from email.utils import formataddr
from typing import Protocol

from app.config import Settings, get_settings


class EmailDeliveryError(RuntimeError):
    pass


class EmailSender(Protocol):
    available: bool

    async def send_login_code(self, recipient: str, code: str, ttl_seconds: int) -> None: ...

    async def preflight(self) -> None: ...


_smtp_verified = False
_smtp_failure_generation = 0
_smtp_probe_requested: asyncio.Event | None = None


def is_smtp_verified() -> bool:
    return _smtp_verified


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

    async def send_login_code(self, recipient: str, code: str, ttl_seconds: int) -> None:
        raise EmailDeliveryError("email login is unavailable")

    async def preflight(self) -> None:
        raise EmailDeliveryError("email login is unavailable")


class SMTPEmailSender:
    available = True

    def __init__(self, config: Settings):
        self.config = config

    async def send_login_code(self, recipient: str, code: str, ttl_seconds: int) -> None:
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

    def _message(self, *, recipient: str, subject: str, body: str) -> EmailMessage:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = formataddr((self.config.smtp_from_name, self.config.smtp_from_email))
        message["To"] = recipient
        message.set_content(body)
        return message

    def _send_sync(self, recipient: str, code: str, ttl_seconds: int) -> None:
        minutes = max(1, ttl_seconds // 60)
        message = self._message(
            recipient=recipient,
            subject="登录验证码",
            body=f"你的登录验证码是：{code}\n\n验证码将在 {minutes} 分钟后失效。若非本人操作，请忽略此邮件。",
        )

        with self._connection() as client:
            client.send_message(message)


def get_email_sender() -> EmailSender:
    config = get_settings()
    if not is_email_login_available(config):
        return DisabledEmailSender()
    return SMTPEmailSender(config)


async def monitor_smtp_verification(
    config: Settings,
    *,
    retry_seconds: float = 30.0,
    max_retry_seconds: float = 300.0,
) -> None:
    """启动和故障恢复均使用真实 acceptance 预检，成功后等待下一次失效信号。"""
    global _smtp_probe_requested
    sender = SMTPEmailSender(config)
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
