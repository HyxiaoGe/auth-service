from functools import lru_cache

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

    # SSO IdP session (Redis-backed session + cookie) for cross-app single sign-on
    session_cookie_samesite: str = "lax"
    session_cookie_domain: str | None = None  # None => host-only cookie (required by __Host- prefix)
    session_ttl_seconds: int = 604800  # 7-day sliding window
    session_absolute_max_seconds: int = 2592000  # 30-day hard cap regardless of activity

    # Auth service base URL
    auth_base_url: str = "http://192.168.1.10:8100"

    # CORS
    cors_origins: str = "http://localhost:3000,http://localhost:3001,http://localhost:5173,http://192.168.1.10:3004"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def session_cookie_name(self) -> str:
        # __Host- prefix mandates Secure + Path=/ + no Domain; only valid over HTTPS (prod).
        # Dev runs over http://localhost where Secure (and thus __Host-) is impossible.
        return "__Host-sso_session" if self.is_production else "sso_session"

    @property
    def session_cookie_secure(self) -> bool:
        # Derived (not a settable field) so production can never be misconfigured insecure.
        return self.is_production

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
