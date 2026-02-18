from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.routers import admin, auth, oauth
from app.security.jwt_handler import get_jwks
from app.utils.redis import close_redis

settings = get_settings()


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
