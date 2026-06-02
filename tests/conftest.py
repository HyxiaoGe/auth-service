"""Shared pytest fixtures.

The whole suite runs against an in-memory fakeredis so tests never touch a real
Redis. We swap the module-level singleton in ``app.utils.redis`` directly, which
makes the module-local ``get_redis()`` (and every helper that calls it) return the
fake client for the duration of each test.
"""

import fakeredis.aioredis
import pytest

import app.security.revocation as revocation_util
import app.utils.redis as redis_util


@pytest.fixture(autouse=True)
async def fake_redis():
    """Back every test's Redis with an in-memory fakeredis (decode_responses=True).

    ``app.utils.redis`` (sessions/auth-codes) and ``app.security.revocation`` (SLO marker) keep
    separate client singletons -- in production, two pools to the same shared instance. Tests
    point both at the SAME fake so a logout's marker write and the deps' read round-trip.
    """
    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    redis_util.redis_client = fake
    revocation_util.redis_client = fake
    yield fake
    await fake.aclose()
    redis_util.redis_client = None
    revocation_util.redis_client = None
