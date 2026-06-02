import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.routers import admin, auth, oauth
from app.security.jwt_handler import get_jwks
from app.utils.redis import close_redis

settings = get_settings()

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
    # Startup
    yield
    # Shutdown
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
)

# ==================== Routers ====================

app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(admin.router)


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
