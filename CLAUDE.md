# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Summary

Centralized authentication microservice (FastAPI + Python 3.12) that issues RS256-signed JWTs for multiple downstream applications. Each downstream app registers as an `Application` with a `client_id`/`client_secret`; tokens carry the app's `client_id` in the `aud` claim. Downstream services validate tokens via the `/.well-known/jwks.json` JWKS endpoint using the `auth-client` pip package (located in `auth-client/`).

## Build & Run

```bash
# Start all services (auth + postgres + redis)
# Requires external Docker network: docker network create nano-banana-network
docker compose up -d

# Apply database migrations
docker compose exec auth alembic upgrade head

# Bootstrap admin user + first application
docker compose exec auth python scripts/init_admin.py

# Run without Docker
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8100 --reload
```

## Database Migrations (Alembic)

```bash
alembic upgrade head                              # apply all
alembic revision --autogenerate -m "description"  # generate from model changes
alembic downgrade -1                              # rollback one
```

Note: `alembic/env.py` overrides the URL in `alembic.ini` with `DATABASE_URL_SYNC` from settings. Two database URLs are required: `DATABASE_URL` (async, `postgresql+asyncpg://`) for runtime and `DATABASE_URL_SYNC` (sync, `postgresql://`) for Alembic.

## Key Generation

```bash
python scripts/generate_keys.py   # creates keys/private.pem and keys/public.pem
```

The `keys/` directory is gitignored and must be generated locally.

## Architecture

### Layer Separation
- **Routers** (`app/routers/`) — HTTP concerns only (request parsing, response models), no business logic
- **Services** (`app/services/`) — All business logic; module-level functions, not class-based (import as `from app.services import auth_service`)
- **Security** (`app/security/`) — JWT handling, FastAPI auth dependencies, password hashing; fully decoupled from routers
- **Models** (`app/models/`) — SQLAlchemy ORM models (all in `__init__.py`)
- **Schemas** (`app/schemas/`) — Pydantic request/response schemas (all in `__init__.py`)

### JWT Strategy
- RS256 asymmetric keys: auth service signs with private key, consumers verify with public key via JWKS
- Access tokens: 15-min expiry; Refresh tokens: 30-day expiry, stored in DB as SHA256 hash, rotated on use
- Token reuse detection: reusing a revoked refresh token triggers revocation of all user tokens
- Scopes: `["admin"]` for superusers, `["user"]` for regular users; enforced via `require_scopes()` dependency

### Social Login (OAuth)
- Google and GitHub supported
- Flow: check `SocialAccount` link → fall back to email lookup → create user if needed → link provider → issue tokens
- App `client_id` + `redirect_uri` are encoded in the OAuth `state` parameter (base64 JSON)
- OAuth callbacks do NOT return tokens directly — they generate a short-lived auth code stored in Redis, redirect to the frontend, and the frontend exchanges the code via `POST /auth/oauth/token`
- `redirect_uri` is validated against the app's registered `redirect_uris`

### Redis
- Used for JWT blacklisting (JTI-based with TTL via `SETEX`) and short-lived OAuth auth codes (5-min TTL)
- Initialized lazily, closed on shutdown via FastAPI `lifespan`

### Password Hashing
- Argon2 via `pwdlib` (not bcrypt) — see `app/security/password.py`

### Async Throughout
All database operations (SQLAlchemy `AsyncSession`), Redis access, and OAuth HTTP calls (`httpx.AsyncClient`) are fully async.

## Configuration

All config via environment variables loaded by `pydantic-settings` from `.env` (copy `.env.example`). Settings are singleton-cached via `@lru_cache` on `get_settings()`. The app runs on port 8100 by default.

## Client SDK (`auth-client/`)

Pip-installable package for downstream FastAPI services. Provides `JWTValidator` (sync + async JWKS-cached verification) and FastAPI dependencies (`require_auth()`, `require_scopes()`).

## API Route Prefixes

- `/auth/*` — Registration, login, token refresh/revoke, userinfo, profile update
- `/auth/oauth/*` — Google/GitHub OAuth flows and token exchange
- `/admin/*` — App management and login logs (requires `admin` scope)
- `/.well-known/jwks.json` — Public JWKS endpoint (no auth)
- `/health` — Health check

## Deployment

CI/CD via GitHub Actions (`.github/workflows/deploy.yml`): push to `main` triggers deploy on a self-hosted runner at `~/project/auth-service`. The workflow does `git reset --hard origin/main` → `docker compose up -d --build` → prune images.

## No Tests or Linting

There are currently no tests, test configuration, or linting/formatting tools configured in this repository.
