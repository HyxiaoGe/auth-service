"""Resend 响应头用量的脱敏 Redis 月度快照。"""

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

from redis.exceptions import WatchError

from app.config import Settings
from app.utils.redis import get_redis

SNAPSHOT_PREFIX = "email_usage:resend:"
SNAPSHOT_TTL_SECONDS = 400 * 24 * 60 * 60


def _period(now: datetime | None = None) -> tuple[str, str, str]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    next_start = (
        start.replace(year=start.year + 1, month=1)
        if start.month == 12
        else start.replace(month=start.month + 1)
    )
    end = next_start - timedelta(microseconds=1)
    return start.strftime("%Y-%m"), start.isoformat(), end.isoformat()


def _nonnegative_integer(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value.strip())
    except (AttributeError, TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _response_datetime(headers: Mapping[str, str]) -> datetime:
    raw = headers.get("date")
    if raw:
        try:
            parsed = parsedate_to_datetime(raw)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        except (TypeError, ValueError):
            pass
    return datetime.now(UTC)


def _decode_snapshot(raw: str | bytes | None) -> dict | None:
    if not raw:
        return None
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _snapshot_datetime(snapshot: dict | None) -> datetime | None:
    raw = snapshot.get("provider_observed_at") if snapshot else None
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _merge_snapshot(
    existing: dict | None,
    headers: Mapping[str, str],
    *,
    period_start: str,
    period_end: str,
    provider_observed_at: datetime,
) -> dict:
    used_emails = _nonnegative_integer(headers.get("x-resend-monthly-quota"))
    existing_used = existing.get("used_emails") if existing else None
    existing_observed_at = _snapshot_datetime(existing)
    preserve_existing = isinstance(existing_used, int) and (
        used_emails is None
        or existing_used > used_emails
        or (
            existing_used == used_emails
            and existing_observed_at is not None
            and existing_observed_at > provider_observed_at
        )
    )
    if preserve_existing:
        return existing

    def header_or_existing(header_name: str, field_name: str) -> int | None:
        current = _nonnegative_integer(headers.get(header_name))
        previous = existing.get(field_name) if existing else None
        return current if current is not None else previous if isinstance(previous, int) else None

    return {
        "used_emails": used_emails,
        "daily_used_emails": header_or_existing(
            "x-resend-daily-quota", "daily_used_emails"
        ),
        "rate_limit": header_or_existing("ratelimit-limit", "rate_limit"),
        "rate_limit_remaining": header_or_existing(
            "ratelimit-remaining", "rate_limit_remaining"
        ),
        "rate_limit_reset_seconds": header_or_existing(
            "ratelimit-reset", "rate_limit_reset_seconds"
        ),
        "period_start": period_start,
        "period_end": period_end,
        "synced_at": datetime.now(UTC).isoformat(),
        "provider_observed_at": provider_observed_at.isoformat(),
        "source": "resend_response_headers",
    }


async def record_resend_usage(headers: Mapping[str, str]) -> None:
    """仅持久允许列表中的数字头，绝不写入响应体、邮箱或请求内容。"""
    provider_observed_at = _response_datetime(headers)
    key_suffix, period_start, period_end = _period(provider_observed_at)
    redis_client = await get_redis()
    key = f"{SNAPSHOT_PREFIX}{key_suffix}"
    while True:
        pipe = redis_client.pipeline()
        try:
            await pipe.watch(key)
            existing = _decode_snapshot(await pipe.get(key))
            snapshot = _merge_snapshot(
                existing,
                headers,
                period_start=period_start,
                period_end=period_end,
                provider_observed_at=provider_observed_at,
            )
            pipe.multi()
            pipe.setex(
                key,
                SNAPSHOT_TTL_SECONDS,
                json.dumps(snapshot, separators=(",", ":")),
            )
            await pipe.execute()
            return
        except WatchError:
            continue
        finally:
            await pipe.reset()


async def get_email_usage(config: Settings) -> dict:
    key_suffix, period_start, period_end = _period()
    if not config.resend_api_key:
        daily_quota = config.resend_daily_quota if isinstance(config.resend_daily_quota, int) else None
        return {
            "provider": "resend",
            "configured": False,
            "available": False,
            "used_emails": None,
            "monthly_quota": config.resend_monthly_quota,
            "remaining_emails": None,
            "usage_ratio": None,
            "daily_used_emails": None,
            "daily_quota": daily_quota,
            "period_start": period_start,
            "period_end": period_end,
            "synced_at": None,
            "source": "not_configured",
        }

    redis_client = await get_redis()
    raw = await redis_client.get(f"{SNAPSHOT_PREFIX}{key_suffix}")
    try:
        decoded = json.loads(raw) if raw else None
        snapshot = decoded if isinstance(decoded, dict) else None
    except (TypeError, ValueError):
        snapshot = None
    used = snapshot.get("used_emails") if snapshot else None
    available = isinstance(used, int) and used >= 0
    daily_quota = config.resend_daily_quota if isinstance(config.resend_daily_quota, int) else None
    return {
        "provider": "resend",
        "configured": True,
        "available": available,
        "used_emails": used if available else None,
        "monthly_quota": config.resend_monthly_quota,
        "remaining_emails": max(config.resend_monthly_quota - used, 0) if available else None,
        "usage_ratio": used / config.resend_monthly_quota if available else None,
        "daily_used_emails": snapshot.get("daily_used_emails") if snapshot and available else None,
        "daily_quota": daily_quota,
        "period_start": snapshot.get("period_start", period_start) if snapshot else period_start,
        "period_end": snapshot.get("period_end", period_end) if snapshot else period_end,
        "synced_at": snapshot.get("synced_at") if snapshot and available else None,
        "source": (
            snapshot.get("source", "resend_response_headers")
            if snapshot and available
            else "not_synced"
        ),
    }
