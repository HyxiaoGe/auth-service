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
import uuid
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
        brand_name: str | None = None,
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


def resolve_brand_name(config: Settings, brand_name: str | None) -> str:
    """邮件里写哪个名字：优先发起登录的应用名（applications.name），没有就退回全局的 SMTP_FROM_NAME，再退回发件地址。"""
    return (brand_name or "").strip() or config.smtp_from_name.strip() or config.smtp_from_email


def login_code_content(brand_name: str, code: str, ttl_seconds: int, recipient: str) -> tuple[str, str, str]:
    """登录验证码邮件的 (主题, 纯文本, HTML)。SMTP 和 Resend 两个发信器共用，别各写一份。

    写法上照着“一眼看出是验证码、别被当成垃圾邮件”来：主题带应用名和验证码；正文说清是谁、
    为什么收到、不是本人怎么办；写明发给哪个邮箱、自动发送请勿回复；纯文本和 HTML 内容一致；
    HTML 只用内联样式和表格布局，不放图片、脚本和外链。
    """
    minutes = max(1, ttl_seconds // 60)
    b, c, r = escape(brand_name), escape(code), escape(recipient)
    subject = f"{brand_name} 登录验证码：{code}"
    text = (
        f"{brand_name} 登录验证码\n"
        f"\n"
        f"你正在用邮箱 {recipient} 登录 {brand_name}，验证码是：\n"
        f"\n"
        f"    {code}\n"
        f"\n"
        f"验证码 {minutes} 分钟内有效，只能用一次，请回到登录页面填写。\n"
        f"如果不是你本人在登录，忽略这封邮件就行，账号不会有任何变化。\n"
        f"\n"
        f"——\n"
        f"这封邮件由 {brand_name} 登录系统自动发送，请勿直接回复。"
    )
    html = (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="x-apple-disable-message-reformatting">'
        f"<title>{b} 登录验证码</title></head>"
        '<body style="margin:0;padding:0;background:#f4f5f7;">'
        # 预览文字：收件箱列表里主题后面那一句
        '<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#f4f5f7;">'
        f"验证码 {c}，{minutes} 分钟内有效。</div>"
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f4f5f7;">'
        '<tr><td align="center" style="padding:32px 16px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="max-width:480px;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;">'
        "<tr><td style=\"padding:28px 32px 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"
        "'PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;\">"
        f'<div style="font-size:15px;font-weight:600;color:#6b7280;letter-spacing:.02em;">{b}</div>'
        '<h1 style="margin:14px 0 0;font-size:22px;line-height:30px;font-weight:600;color:#111827;">登录验证码</h1>'
        f'<p style="margin:12px 0 0;font-size:15px;line-height:24px;color:#374151;">'
        f'你正在用邮箱 <span style="color:#111827;">{r}</span> 登录 {b}，请在登录页面填写下面的验证码：</p>'
        "</td></tr>"
        '<tr><td style="padding:20px 32px 0;">'
        '<div style="background:#f3f4f6;border-radius:10px;padding:18px 0;text-align:center;'
        "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Courier New',monospace;"
        f'font-size:32px;line-height:40px;font-weight:700;letter-spacing:10px;color:#111827;">{c}</div>'
        "</td></tr>"
        "<tr><td style=\"padding:16px 32px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"
        "'PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;\">"
        f'<p style="margin:0;font-size:14px;line-height:22px;color:#374151;">验证码 {minutes} 分钟内有效，只能用一次。</p>'
        '<p style="margin:8px 0 0;font-size:14px;line-height:22px;color:#6b7280;">'
        "如果不是你本人在登录，忽略这封邮件就行，账号不会有任何变化。</p>"
        "</td></tr>"
        "</table>"
        "<p style=\"margin:16px 0 0;max-width:480px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"
        "'PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;font-size:12px;line-height:18px;color:#9ca3af;\">"
        f"这封邮件发送至 {r}，由 {b} 登录系统自动发送，请勿直接回复。</p>"
        "</td></tr></table></body></html>"
    )
    return subject, text, html


class DisabledEmailSender:
    available = False

    async def send_login_code(
        self,
        recipient: str,
        code: str,
        ttl_seconds: int,
        delivery_id: str | None = None,
        brand_name: str | None = None,
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
        brand_name: str | None = None,
    ) -> None:
        try:
            await asyncio.to_thread(
                self._send_sync, recipient, code, ttl_seconds, resolve_brand_name(self.config, brand_name)
            )
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
        from_name: str | None = None,
    ) -> EmailMessage:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = formataddr((from_name or self.config.smtp_from_name, self.config.smtp_from_email))
        message["To"] = recipient
        message["Date"] = formatdate(localtime=False, usegmt=True)
        sender_domain = parseaddr(self.config.smtp_from_email)[1].rpartition("@")[2] or None
        message["Message-ID"] = make_msgid(domain=sender_domain)
        message["Auto-Submitted"] = "auto-generated"
        message["X-Auto-Response-Suppress"] = "All"  # 让 Outlook 之类别对它发自动回复 / 外出通知
        message["X-Entity-Ref-ID"] = uuid.uuid4().hex  # 每封不同，Gmail 不会把几次验证码串成一个会话
        message.set_content(body)
        if html_body is not None:
            message.add_alternative(html_body, subtype="html")
        return message

    def _send_sync(self, recipient: str, code: str, ttl_seconds: int, brand_name: str) -> None:
        subject, body, html_body = login_code_content(brand_name, code, ttl_seconds, recipient)
        message = self._message(
            recipient=recipient, subject=subject, body=body, html_body=html_body, from_name=brand_name
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
        brand_name: str | None = None,
    ) -> None:
        brand = resolve_brand_name(self.config, brand_name)
        subject, text, html = login_code_content(brand, code, ttl_seconds, recipient)
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
                subject=subject,
                text=text,
                html=html,
                from_name=brand,
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
        from_name: str | None = None,
    ) -> None:
        sender = formataddr((from_name or self.config.smtp_from_name, self.config.smtp_from_email))
        payload = {
            "from": sender,
            "to": [recipient],
            "subject": subject,
            "text": text,
            "headers": {
                "Auto-Submitted": "auto-generated",
                "X-Auto-Response-Suppress": "All",
                "X-Entity-Ref-ID": uuid.uuid4().hex,
            },
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
                revokes_global_readiness=(status_code in (401, 403) or status_code >= 500),
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
