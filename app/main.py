import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from ipaddress import ip_address

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.config import Settings, get_settings
from app.database import engine
from app.routers import admin, auth, oauth, password_auth
from app.security.jwt_handler import get_jwks
from app.services import email_sender
from app.utils.redis import close_redis, get_redis

settings = get_settings()
READINESS_TIMEOUT_SECONDS = 2.0
EMAIL_DELIVERY_VERIFICATION_SMTP_PHASES = 4
EMAIL_DELIVERY_VERIFICATION_GRACE_SECONDS = 10.0

# App logging: the service previously emitted nothing to stdout/stderr (audit lived only in
# the LoginLog table). uvicorn configures only its own uvicorn.* loggers and does NOT add a
# root handler, so app.* INFO records would otherwise be dropped. This module is imported
# after uvicorn has applied its dict-config, so basicConfig runs last and installs the
# missing root handler at INFO -- surfacing the oauth_state.create/consume/missing
# diagnostics in `docker logs`. (basicConfig only no-ops if a root handler already exists,
# which uvicorn's default config does not create; should that ever change, app.* logs would
# silently fall back to WARNING and this line would need an explicit handler instead.)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    smtp_monitor_task: asyncio.Task | None = None
    if settings.email_login_ready:
        email_sender.invalidate_smtp_verification()
        smtp_monitor_task = asyncio.create_task(
            email_sender.monitor_smtp_verification(settings),
            name="smtp-verification-monitor",
        )
    try:
        yield
    finally:
        if smtp_monitor_task is not None:
            smtp_monitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await smtp_monitor_task
        await close_redis()


app = FastAPI(
    title="Auth Service",
    description="Unified authentication & authorization service",
    version="1.0.0",
    lifespan=lifespan,
)

# ==================== CORS ====================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Retry-After"],
)

# ==================== Routers ====================


def include_password_auth_router(target_app: FastAPI, config: Settings) -> None:
    """仅在显式配置完整时注册隐藏的内部账密兼容端点。"""
    if config.password_auth_enabled:
        target_app.include_router(
            password_auth.create_router(
                config.password_auth_internal_token,
                config.password_auth_email_prefix,
                config.password_auth_email_domain,
            )
        )


app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(admin.router)
include_password_auth_router(app, settings)


# ==================== JWKS Endpoint ====================


@app.get("/.well-known/jwks.json", tags=["Discovery"])
async def jwks():
    """
    JSON Web Key Set endpoint.
    Business services use this to verify JWT tokens without sharing secrets.
    """
    return JSONResponse(content=get_jwks())


# ==================== Health Check ====================


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "service": settings.app_name}


async def _check_database() -> None:
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))


async def _check_redis() -> None:
    redis_client = await get_redis()
    if not await redis_client.ping():
        raise RuntimeError("Redis ping failed")


async def _check_readiness_dependencies() -> None:
    async with asyncio.TaskGroup() as group:
        group.create_task(_check_database())
        group.create_task(_check_redis())


def _is_loopback_request(request: Request) -> bool:
    if request.client is None:
        return False
    try:
        return ip_address(request.client.host).is_loopback
    except ValueError:
        return False


def _internal_health_forbidden() -> JSONResponse:
    return JSONResponse(status_code=403, content={"status": "forbidden"})


@app.get("/health/ready", tags=["Health"])
async def health_ready(request: Request):
    """部署 readiness：核心持久化依赖都可用才允许切换流量。"""
    if not _is_loopback_request(request):
        return _internal_health_forbidden()
    try:
        await asyncio.wait_for(
            _check_readiness_dependencies(),
            timeout=READINESS_TIMEOUT_SECONDS,
        )
    except Exception:
        logging.getLogger(__name__).exception("readiness dependency check failed")
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "service": settings.app_name},
        )
    return {"status": "ready", "service": settings.app_name}


@app.get("/health/email-delivery", tags=["Health"])
async def email_delivery_health(request: Request):
    """内部 SMTP 投递状态：限时等待后台 monitor 的接收级预检结果。"""
    if not _is_loopback_request(request):
        return _internal_health_forbidden()
    if not settings.email_login_enabled:
        email_sender.invalidate_smtp_verification()
        return {"status": "disabled", "service": settings.app_name}
    if not settings.email_login_ready:
        email_sender.invalidate_smtp_verification()
        return JSONResponse(
            status_code=503,
            content={"status": "misconfigured", "service": settings.app_name},
        )
    # SMTP socket timeout may apply independently to connect、STARTTLS、auth 和 send。
    # health 等待完整阶段预算，避免正常但较慢的首次 monitor 预检被提前误判为失败。
    verification_wait_seconds = (
        settings.smtp_timeout_seconds * EMAIL_DELIVERY_VERIFICATION_SMTP_PHASES
        + EMAIL_DELIVERY_VERIFICATION_GRACE_SECONDS
    )
    try:
        verified = await email_sender.wait_for_smtp_verification(
            verification_wait_seconds,
        )
    except Exception:
        logging.getLogger(__name__).warning("waiting for SMTP verification failed", exc_info=True)
        verified = False
    if not verified or not email_sender.is_smtp_verified():
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "service": settings.app_name},
        )
    return {
        "status": "ready",
        "service": settings.app_name,
        "verification": "smtp_accepted_only",
    }
