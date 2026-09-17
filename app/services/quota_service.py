"""Atomic Redis quota reservations with PostgreSQL reconciliation."""

import time
from dataclasses import dataclass
from uuid import uuid4

from fastapi import HTTPException, status

from app.core.config import get_settings
from app.core.database import get_pool
from app.core.redis_client import get_redis

settings = get_settings()

_RESERVE = """
local usage = KEYS[1]
local reservation = KEYS[2]
local reservations = KEYS[3]
local secret_delta = tonumber(ARGV[1])
local byte_delta = tonumber(ARGV[2])
local secret_limit = tonumber(ARGV[3])
local byte_limit = tonumber(ARGV[4])
local expires_at = tonumber(ARGV[5])
if redis.call('EXISTS', usage) == 0 then
  redis.call('HSET', usage, 'secrets', tonumber(ARGV[7]), 'bytes', tonumber(ARGV[8]))
end
local current_secrets = tonumber(redis.call('HGET', usage, 'secrets') or '0')
local current_bytes = tonumber(redis.call('HGET', usage, 'bytes') or '0')
if current_secrets + secret_delta > secret_limit then return {0, 1, current_secrets, current_bytes} end
if current_bytes + byte_delta > byte_limit then return {0, 2, current_secrets, current_bytes} end
redis.call('HINCRBY', usage, 'secrets', secret_delta)
redis.call('HINCRBY', usage, 'bytes', byte_delta)
redis.call('HSET', reservation, 'secret_delta', secret_delta, 'byte_delta', byte_delta, 'user_id', ARGV[6], 'committed', 0)
redis.call('ZADD', reservations, expires_at, reservation)
return {1, 0, current_secrets + secret_delta, current_bytes + byte_delta}
"""

_RELEASE = """
local usage = KEYS[1]
local reservation = KEYS[2]
local reservations = KEYS[3]
if redis.call('EXISTS', reservation) == 0 then return 0 end
if redis.call('HGET', reservation, 'committed') == '0' then
  redis.call('HINCRBY', usage, 'secrets', -tonumber(redis.call('HGET', reservation, 'secret_delta') or '0'))
  redis.call('HINCRBY', usage, 'bytes', -tonumber(redis.call('HGET', reservation, 'byte_delta') or '0'))
end
redis.call('DEL', reservation)
redis.call('ZREM', reservations, reservation)
return 1
"""

_COMMIT = """
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('HSET', KEYS[1], 'committed', 1)
redis.call('ZREM', KEYS[2], KEYS[1])
redis.call('DEL', KEYS[1])
return 1
"""

_RECONCILE = """
local secrets = tonumber(ARGV[2])
local bytes = tonumber(ARGV[3])
for _, reservation in ipairs(redis.call('ZRANGE', KEYS[2], 0, -1)) do
  if redis.call('HGET', reservation, 'user_id') == ARGV[1]
     and redis.call('HGET', reservation, 'committed') == '0' then
    secrets = secrets + tonumber(redis.call('HGET', reservation, 'secret_delta') or '0')
    bytes = bytes + tonumber(redis.call('HGET', reservation, 'byte_delta') or '0')
  end
end
redis.call('HSET', KEYS[1], 'secrets', secrets, 'bytes', bytes)
return {secrets, bytes}
"""


@dataclass
class Reservation:
    id: str
    user_id: str
    secret_delta: int
    byte_delta: int


def _usage_key(user_id: str) -> str:
    return f"phantom:quota:{user_id}:usage"


def _reservation_key(reservation_id: str) -> str:
    return f"phantom:quota:reservation:{reservation_id}"


async def limits_for_user(user_id: str) -> tuple[int, int]:
    async with get_pool().connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT max_active_secrets, max_file_bytes FROM user_quotas WHERE user_id = %s",
                (user_id,),
            )
            row = await cur.fetchone()
    return (
        row[0] if row and row[0] is not None else settings.DEFAULT_MAX_ACTIVE_SECRETS,
        row[1] if row and row[1] is not None else settings.DEFAULT_MAX_FILE_STORAGE_BYTES,
    )


async def durable_usage(user_id: str) -> tuple[int, int]:
    async with get_pool().connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT COUNT(*) FROM secrets WHERE owner_id = %s",
                (user_id,),
            )
            secrets_count = (await cur.fetchone())[0]
            await cur.execute(
                """
                SELECT COALESCE(SUM(v.plaintext_size), 0)
                FROM secret_versions v JOIN secrets s ON s.id = v.secret_id
                WHERE s.owner_id = %s AND v.object_key IS NOT NULL
                """,
                (user_id,),
            )
            active_bytes = (await cur.fetchone())[0]
            await cur.execute(
                """
                SELECT COALESCE(SUM(billed_bytes), 0) FROM object_deletion_outbox
                WHERE user_id = %s AND processed_at IS NULL
                """,
                (user_id,),
            )
            pending_bytes = (await cur.fetchone())[0]
    return int(secrets_count), int(active_bytes + pending_bytes)


async def reconcile_user(user_id: str) -> tuple[int, int]:
    try:
        redis = get_redis()
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Quota service unavailable") from exc
    secret_count, file_bytes = await durable_usage(user_id)
    reconciled = await redis.eval(
        _RECONCILE, 2, _usage_key(user_id), "phantom:quota:reservations",
        user_id, secret_count, file_bytes,
    )
    return int(reconciled[0]), int(reconciled[1])


async def reserve(user_id: str, *, secrets: int = 0, file_bytes: int = 0) -> Reservation:
    try:
        redis = get_redis()
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Quota service unavailable") from exc
    usage_key = _usage_key(user_id)
    durable_secrets, durable_bytes = await durable_usage(user_id)
    secret_limit, byte_limit = await limits_for_user(user_id)
    reservation_id = str(uuid4())
    reservation_key = _reservation_key(reservation_id)
    result = await redis.eval(
        _RESERVE, 3, usage_key, reservation_key, "phantom:quota:reservations",
        secrets, file_bytes, secret_limit, byte_limit, int(time.time()) + 600, user_id,
        durable_secrets, durable_bytes,
    )
    if not int(result[0]):
        code = "MAX_ACTIVE_SECRETS" if int(result[1]) == 1 else "MAX_FILE_STORAGE"
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "error_code": "QUOTA_EXCEEDED", "quota": code,
                "active_secrets": int(result[2]), "file_bytes": int(result[3]),
                "max_active_secrets": secret_limit, "max_file_bytes": byte_limit,
            },
        )
    return Reservation(reservation_id, user_id, secrets, file_bytes)


async def commit(reservation: Reservation) -> None:
    redis = get_redis()
    await redis.eval(
        _COMMIT, 2, _reservation_key(reservation.id), "phantom:quota:reservations"
    )


async def reap_expired_reservations() -> int:
    """Release abandoned reservations after crashed or timed-out requests."""
    redis = get_redis()
    keys = await redis.zrangebyscore("phantom:quota:reservations", 0, int(time.time()))
    released = 0
    for key in keys:
        values = await redis.hgetall(key)
        user_id = values.get("user_id")
        if user_id:
            await release(Reservation(
                key.rsplit(":", 1)[-1], user_id,
                int(values.get("secret_delta", 0)), int(values.get("byte_delta", 0)),
            ))
            released += 1
        else:
            await redis.delete(key)
            await redis.zrem("phantom:quota:reservations", key)
    return released


async def release(reservation: Reservation) -> None:
    try:
        redis = get_redis()
        await redis.eval(
            _RELEASE, 3, _usage_key(reservation.user_id),
            _reservation_key(reservation.id), "phantom:quota:reservations",
        )
    except Exception:
        # Reconciliation corrects drift; never hide the original operation error.
        return


async def usage(user_id: str) -> dict:
    current_secrets, current_bytes = await reconcile_user(user_id)
    max_secrets, max_bytes = await limits_for_user(user_id)
    return {
        "active_secrets": current_secrets,
        "file_bytes": current_bytes,
        "max_active_secrets": max_secrets,
        "max_file_bytes": max_bytes,
    }
