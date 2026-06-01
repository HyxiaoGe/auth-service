"""Redis-backed SSO session storage primitives (sso_session:<sid>)."""

from app.utils import redis as redis_util


async def test_create_then_get_roundtrips_payload():
    await redis_util.create_session("sid1", {"user_id": "u1", "amr": ["google"]}, ttl=100)
    assert await redis_util.get_session("sid1") == {"user_id": "u1", "amr": ["google"]}


async def test_get_missing_returns_none():
    assert await redis_util.get_session("does-not-exist") is None


async def test_create_sets_ttl(fake_redis):
    await redis_util.create_session("sid2", {"user_id": "u2"}, ttl=123)
    ttl = await fake_redis.ttl("sso_session:sid2")
    assert 0 < ttl <= 123


async def test_touch_resets_ttl(fake_redis):
    await redis_util.create_session("sid3", {"user_id": "u3"}, ttl=10)
    await redis_util.touch_session("sid3", ttl=500)
    assert await fake_redis.ttl("sso_session:sid3") > 100


async def test_delete_removes_session():
    await redis_util.create_session("sid4", {"user_id": "u4"}, ttl=100)
    await redis_util.delete_session("sid4")
    assert await redis_util.get_session("sid4") is None


async def test_session_key_is_namespaced(fake_redis):
    # Isolation matters: the Redis instance may be shared on nano-banana-network.
    await redis_util.create_session("sid5", {"user_id": "u5"}, ttl=100)
    assert await fake_redis.exists("sso_session:sid5") == 1
