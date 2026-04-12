# Coding Conventions

## Linting

- Ruff for linting and formatting (config in `pyproject.toml`)
- Run: `ruff check . && ruff format .`
- Rules: E, F, I, UP, B, SIM (ignoring E501 and B008)
- Line length: 120, target Python 3.12

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

## Configuration

All config via environment variables loaded by `pydantic-settings` from `.env` (copy `.env.example`). Settings are singleton-cached via `@lru_cache` on `get_settings()`. The app runs on port 8100 by default.

## Client SDK (`auth-client/`)

Pip-installable package for downstream FastAPI services. Provides `JWTValidator` (sync + async JWKS-cached verification) and FastAPI dependencies (`require_auth()`, `require_scopes()`).

## Architecture Check

```bash
python scripts/check_architecture.py   # validates import layer dependencies
```
