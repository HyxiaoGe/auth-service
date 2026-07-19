from functools import lru_cache
from ipaddress import ip_network
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    app_name: str = "auth-service"
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8100
    app_debug: bool = True

    # Database
    database_url: str = "postgresql+asyncpg://sean:sean_auth_pass@localhost:5432/auth"
    database_url_sync: str = "postgresql://sean:sean_auth_pass@localhost:5432/auth"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # JWT
    jwt_private_key_path: str = "keys/private.pem"
    jwt_public_key_path: str = "keys/public.pem"
    jwt_algorithm: str = "RS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    # Rotation grace: a refresh token whose rotation response was lost gets replayed by the
    # client within this many seconds = a network retry, not a reuse attack. Re-issue its
    # successor ONCE instead of revoking everything. Narrow on purpose (Auth0 defaults 30s; the
    # real trigger here is sub-10s tunnel retries). Set 0 to disable (rollback switch) -- reuse
    # detection then reverts to the original revoke-all behavior.
    refresh_reuse_grace_seconds: int = 5

    # OAuth: Google
    google_client_id: str = ""
    google_client_secret: str = ""

    # OAuth: GitHub
    github_client_id: str = ""
    github_client_secret: str = ""

    # Auth code (OAuth authorization code flow)
    auth_code_expire_seconds: int = 300  # 5-minute one-time code

    # 账密端点仅供受控内部兼容任务使用，默认不注册到应用。
    password_auth_enabled: bool = False
    password_auth_internal_token: str = ""
    password_auth_email_prefix: str = ""
    password_auth_email_domain: str = ""

    # 邮箱验证码登录：所需密钥与发送端配置齐全前保持关闭。
    email_login_enabled: bool = False
    # Headless JSON 登录独立灰度；关闭后不提供邮箱验证码登录入口。
    email_headless_login_enabled: bool = False
    email_code_pepper: str = ""
    email_code_ttl_seconds: int = Field(default=300, gt=0)
    email_flow_ttl_seconds: int = Field(default=600, gt=0)
    email_flow_recovery_ttl_seconds: int = Field(default=3600, gt=0)
    email_code_resend_seconds: int = Field(default=60, gt=0)
    email_code_max_attempts: int = Field(default=5, gt=0)
    email_rate_limit_per_email: int = Field(default=5, gt=0)
    email_rate_limit_per_ip: int = Field(default=20, gt=0)
    email_rate_limit_per_flow: int = Field(default=3, gt=0)
    email_send_rate_limit_global: int = Field(default=1000, gt=0)
    email_authorize_rate_limit_per_ip: int = Field(default=60, gt=0)
    email_authorize_rate_limit_per_client: int = Field(default=2000, gt=0)
    email_authorize_rate_limit_global: int = Field(default=10000, gt=0)
    email_send_request_rate_limit_per_ip: int = Field(default=120, gt=0)
    email_send_request_rate_limit_per_flow: int = Field(default=15, gt=0)
    email_send_request_rate_limit_global: int = Field(default=10000, gt=0)
    email_verify_rate_limit_per_ip: int = Field(default=120, gt=0)
    email_verify_rate_limit_per_flow: int = Field(default=15, gt=0)
    email_verify_rate_limit_global: int = Field(default=10000, gt=0)
    email_rate_limit_window_seconds: int = Field(default=3600, gt=0)
    email_flow_max_per_browser: int = Field(default=5, gt=0)

    # SMTP 发送：STARTTLS 与隐式 TLS 只能二选一。
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_from_name: str = "Sean Auth"
    smtp_smoke_recipient: str = ""
    smtp_starttls: bool = True
    smtp_use_ssl: bool = False
    smtp_allow_plaintext_development: bool = False
    smtp_timeout_seconds: float = Field(default=10.0, gt=0)

    # 只有直连对端命中这些 CIDR 时，才信任其转发的客户端 IP 请求头。
    trusted_proxy_cidrs: str = ""

    # SSO IdP session (Redis-backed session + cookie) for cross-app single sign-on
    session_cookie_samesite: str = "lax"
    session_cookie_domain: str | None = None  # None => host-only cookie (required by __Host- prefix)
    session_ttl_seconds: int = 604800  # 7-day sliding window
    session_absolute_max_seconds: int = 2592000  # 30-day hard cap regardless of activity

    # Auth service base URL
    auth_base_url: str = "http://192.168.1.10:8100"

    # CORS
    cors_origins: str = (
        "http://localhost:3000,http://localhost:3001,http://localhost:5173,http://192.168.1.10:3004,app://-"
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def auth_uses_https(self) -> bool:
        return urlsplit(self.auth_base_url).scheme.lower() == "https"

    @property
    def email_login_ready(self) -> bool:
        return bool(
            self.email_login_enabled
            and len(self.email_code_pepper) >= 32
            and self.smtp_host
            and self.smtp_from_email
            and self.smtp_smoke_recipient
            and not (self.smtp_starttls and self.smtp_use_ssl)
            and (
                self.smtp_starttls
                or self.smtp_use_ssl
                or (
                    self.app_env == "development" and not self.auth_uses_https and self.smtp_allow_plaintext_development
                )
            )
        )

    @property
    def email_headless_login_ready(self) -> bool:
        return self.email_headless_login_enabled and self.email_login_ready

    @property
    def trusted_proxy_networks(self) -> tuple:
        return tuple(
            ip_network(value.strip(), strict=False) for value in self.trusted_proxy_cidrs.split(",") if value.strip()
        )

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def validate_trusted_proxy_cidrs(cls, value: str) -> str:
        for item in value.split(","):
            if item.strip():
                ip_network(item.strip(), strict=False)
        return value

    @field_validator("password_auth_email_prefix", "password_auth_email_domain")
    @classmethod
    def normalize_password_auth_email_scope(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_auth_relationships(self):
        if self.password_auth_enabled and len(self.password_auth_internal_token) < 32:
            raise ValueError("password_auth_internal_token must contain at least 32 characters")
        if self.password_auth_enabled and not self.password_auth_email_prefix:
            raise ValueError("password_auth_email_prefix is required when password auth is enabled")
        if self.password_auth_enabled and not self.password_auth_email_domain:
            raise ValueError("password_auth_email_domain is required when password auth is enabled")
        if self.password_auth_enabled and (
            "@" in self.password_auth_email_prefix or "@" in self.password_auth_email_domain
        ):
            raise ValueError("password_auth_email_prefix and password_auth_email_domain must not contain @")
        if self.email_code_ttl_seconds > self.email_flow_ttl_seconds:
            raise ValueError("email_code_ttl_seconds must be <= email_flow_ttl_seconds")
        if self.email_flow_recovery_ttl_seconds < self.email_flow_ttl_seconds:
            raise ValueError("email_flow_recovery_ttl_seconds must be >= email_flow_ttl_seconds")
        if self.email_send_request_rate_limit_per_flow < self.email_rate_limit_per_flow:
            raise ValueError(
                "email_send_request_rate_limit_per_flow must be >= email_rate_limit_per_flow"
            )
        minimum_verify_attempts = self.email_code_max_attempts * self.email_rate_limit_per_flow
        if self.email_verify_rate_limit_per_flow < minimum_verify_attempts:
            raise ValueError(
                "email_verify_rate_limit_per_flow must be >= "
                "email_code_max_attempts * email_rate_limit_per_flow"
            )
        if self.smtp_starttls and self.smtp_use_ssl:
            raise ValueError("smtp_starttls and smtp_use_ssl are mutually exclusive")
        if self.email_login_enabled and len(self.email_code_pepper) < 32:
            raise ValueError("email_code_pepper must contain at least 32 characters")
        if self.email_login_enabled and not self.smtp_smoke_recipient.strip():
            raise ValueError("smtp_smoke_recipient is required when email login is enabled")
        if (
            self.email_login_enabled
            and not (self.smtp_starttls or self.smtp_use_ssl)
            and (self.app_env != "development" or self.auth_uses_https or not self.smtp_allow_plaintext_development)
        ):
            raise ValueError("plaintext SMTP requires an explicit development-only opt-in")
        if self.email_login_enabled and self.auth_uses_https and not self.trusted_proxy_cidrs.strip():
            raise ValueError("trusted_proxy_cidrs is required when email login is enabled on public HTTPS")
        return self

    @property
    def session_cookie_name(self) -> str:
        # dev HTTPS 原地把既有 sso_session 升级为 Secure，避免仅因本次功能发布改名并遗留旧会话。
        # production 且无 Domain 时再使用 __Host-（其余场景保留无前缀名称）。
        return "__Host-sso_session" if self.is_production and self.session_cookie_domain is None else "sso_session"

    @property
    def session_cookie_secure(self) -> bool:
        # 根据公开地址推导，避免 HTTPS 环境意外发送非 Secure Cookie。
        return self.is_production or self.auth_uses_https

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
