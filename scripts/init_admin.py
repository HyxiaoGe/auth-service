#!/usr/bin/env python3
"""Initialize admin user and register the first application."""

import asyncio
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select
from app.config import get_settings
from app.database import async_session, engine, Base
from app.models import Application, User
from app.security.password import hash_password

settings = get_settings()

ADMIN_EMAIL = "admin@sean.dev"
ADMIN_PASSWORD = "changeme123"  # Change this!


async def init():
    # Create tables if not exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as db:
        # Create admin user
        result = await db.execute(select(User).where(User.email == ADMIN_EMAIL))
        admin = result.scalar_one_or_none()

        if not admin:
            admin = User(
                email=ADMIN_EMAIL,
                name="Sean Admin",
                password_hash=hash_password(ADMIN_PASSWORD),
                is_superuser=True,
            )
            db.add(admin)
            print(f"✅ Admin user created: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")
        else:
            print(f"ℹ️  Admin user already exists: {ADMIN_EMAIL}")

        # Create a sample application
        result = await db.execute(select(Application).where(Application.name == "MovieMate"))
        app = result.scalar_one_or_none()

        if not app:
            client_id = f"app_{secrets.token_hex(16)}"
            client_secret = secrets.token_urlsafe(48)
            app = Application(
                name="MovieMate",
                description="Movie recommendation app",
                client_id=client_id,
                client_secret=client_secret,
                redirect_uris=["http://localhost:3000/callback"],
            )
            db.add(app)
            print(f"✅ Sample app 'MovieMate' registered:")
            print(f"   client_id:     {client_id}")
            print(f"   client_secret: {client_secret}")
            print(f"   ⚠️  Save the client_secret now — it won't be shown again!")
        else:
            print(f"ℹ️  App 'MovieMate' already exists (client_id: {app.client_id})")

        await db.commit()

    print()
    print("🚀 Initialization complete!")
    print(f"   API docs: http://localhost:{settings.app_port}/docs")


if __name__ == "__main__":
    asyncio.run(init())
