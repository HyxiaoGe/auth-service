from pydantic_settings import BaseSettings
from functools import lru_cache


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

    # OAuth: Google
    google_client_id: str = ""
    google_client_secret: str = ""

    # OAuth: GitHub
    github_client_id: str = ""
    github_client_secret: str = ""

    # Auth code (OAuth authorization code flow)
    auth_code_expire_seconds: int = 300  # 5-minute one-time code

    # Auth service base URL
    auth_base_url: str = "http://localhost:8100"

    # CORS
    cors_origins: str = "http://localhost:3000,http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
