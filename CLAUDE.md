# CLAUDE.md

Centralized authentication microservice (FastAPI + Python 3.12) that issues RS256-signed JWTs for multiple downstream applications. Each downstream app registers as an `Application` with a `client_id`/`client_secret`; tokens carry the app's `client_id` in the `aud` claim. Downstream services validate tokens via the `/.well-known/jwks.json` JWKS endpoint using the `auth-client` pip package (located in `auth-client/`).

## Build & Run

```bash
# Start all services (auth + postgres + redis)
# Requires external Docker network: docker network create nano-banana-network
docker compose up -d
docker compose exec auth alembic upgrade head     # apply migrations
docker compose exec auth python scripts/init_admin.py  # bootstrap admin + first app

# Run without Docker
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8100 --reload
```

## Lint & Check

```bash
ruff check . && ruff format .            # lint + format (config in pyproject.toml)
python scripts/check_architecture.py     # validate import layer dependencies
```

## API Route Prefixes

- `/auth/*` -- Registration, login, token refresh/revoke, userinfo, profile update
- `/auth/oauth/*` -- Google/GitHub OAuth flows and token exchange
- `/admin/*` -- App management and login logs (requires `admin` scope)
- `/.well-known/jwks.json` -- Public JWKS endpoint (no auth)
- `/health` -- Health check

## Architecture

Layered architecture with strict import rules. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full details.

- **Routers** (`app/routers/`) -- HTTP layer only, delegates to services
- **Services** (`app/services/`) -- Business logic, module-level functions
- **Security** (`app/security/`) -- JWT, auth deps, password hashing
- **Models/Schemas** (`app/models/`, `app/schemas/`) -- ORM + Pydantic (each in `__init__.py`)
- **Utils** (`app/utils/`) -- Redis client
- **Config** (`app/config.py`) -- pydantic-settings with `@lru_cache`

## Conventions

See [docs/CODING_CONVENTIONS.md](docs/CODING_CONVENTIONS.md) for migrations, key generation, config, and client SDK details.

## Deployment

CI/CD via GitHub Actions (`.github/workflows/deploy.yml`): push to `main` triggers checks (architecture + lint) then deploy on a self-hosted runner at `~/project/auth-service`.
