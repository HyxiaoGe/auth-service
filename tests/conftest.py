"""Shared pytest fixtures.

The whole suite runs against an in-memory fakeredis so tests never touch a real
Redis. We swap the module-level singleton in ``app.utils.redis`` directly, which
makes the module-local ``get_redis()`` (and every helper that calls it) return the
fake client for the duration of each test.
"""

import fakeredis.aioredis
import pytest

import app.utils.redis as redis_util


@pytest.fixture(autouse=True)
async def fake_redis():
    """Back every test's Redis with an in-memory fakeredis (decode_responses=True)."""
    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    redis_util.redis_client = fake
    yield fake
    await fake.aclose()
    redis_util.redis_client = None
