# Architecture

## Layer Separation

- **Routers** (`app/routers/`) -- HTTP concerns only (request parsing, response models), no business logic
- **Services** (`app/services/`) -- All business logic; module-level functions, not class-based (import as `from app.services import auth_service`)
- **Security** (`app/security/`) -- JWT handling, FastAPI auth dependencies, password hashing; fully decoupled from routers
- **Models** (`app/models/`) -- SQLAlchemy ORM models (all in `__init__.py`)
- **Schemas** (`app/schemas/`) -- Pydantic request/response schemas (all in `__init__.py`)
- **Utils** (`app/utils/`) -- Shared utilities (Redis client)
- **Config** (`app/config.py`) -- pydantic-settings, singleton-cached via `@lru_cache`

## Allowed Import Dependencies

```
routers -> services, security, schemas, models, database, config, utils
services -> security, models, schemas, config, utils
security -> config (jwt_handler), security (deps -> jwt_handler)
models   -> database
schemas  -> (no app imports)
utils    -> config
config   -> (no app imports)
database -> config
```

## JWT Strategy

- RS256 asymmetric keys: auth service signs with private key, consumers verify with public key via JWKS
- Access tokens: 15-min expiry; Refresh tokens: 30-day expiry, stored in DB as SHA256 hash, rotated on use
- 中央 Cookie 只保存 secret lookup key；Redis payload 中另存公开 `session_id`。新浏览器流的
  access/auth-code/refresh token 只贯穿公开 `sid`，refresh 数据库行同样绑定该值
- Token reuse detection: reusing a revoked refresh token revokes that application's lineage;
  explicit `/auth/logout/all` alone advances the user-wide authentication generation
- Scopes: `["admin"]` for superusers, `["user"]` for regular users; enforced via `require_scopes()` dependency

## Social Login (OAuth)

- Google and GitHub supported
- Flow: check `SocialAccount` link -> fall back to email lookup -> create user if needed -> link provider -> issue tokens
- App `client_id` + `redirect_uri` are encoded in the OAuth `state` parameter (base64 JSON)
- OAuth callbacks generate a short-lived auth code stored in Redis, redirect to the frontend, and the frontend exchanges the code via `POST /auth/oauth/token`
- `redirect_uri` is validated against the app's registered `redirect_uris`

## Redis

- Used for JWT blacklisting, short-lived OAuth auth codes, IdP sessions, `revoked_sid:{sid}` 与
  显式全设备登出的 `revoked_user:{sub}` marker
- Initialized lazily, closed on shutdown via FastAPI `lifespan`

## Password Hashing

- Argon2 via `pwdlib` (not bcrypt) -- see `app/security/password.py`

## Async Throughout

All database operations (SQLAlchemy `AsyncSession`), Redis access, and OAuth HTTP calls (`httpx.AsyncClient`) are fully async.
