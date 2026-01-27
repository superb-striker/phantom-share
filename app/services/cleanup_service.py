"""
cleanup_service.py – Expiry driven by Redis keyspace notifications.

Flow:
  1. On secret creation, schedule_expiry() sets a Redis key with TTL.
  2. When that key expires, Redis emits a keyspace event.
  3. expiry_worker() is subscribed to those events and deletes the
     specific secret from PostgreSQL immediately.
  4. A fallback DB sweep runs every 10 minutes to catch any secrets
     missed during Redis downtime.
"""
import asyncio

from app.core.database import get_pool
from app.core.redis_client import get_redis
from app.services import audit_service

REDIS_EXPIRY_PREFIX = "phantom:expiry:"
FALLBACK_SWEEP_INTERVAL = 600  # seconds

async def schedule_expiry(secret_id: str, ttl_seconds: int) -> None:
    # Set a Redis sentinel key that expires after ttl_seconds
    redis = get_redis()
    key = f"{REDIS_EXPIRY_PREFIX}{secret_id}"
    await redis.setex(key, ttl_seconds, secret_id)

async def _delete_secret(secret_id: str) -> None:
    # Delete a single secret from PostgreSQL by ID (redis-event driven)
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM secrets WHERE id = %s RETURNING id", (secret_id,)
            )
            deleted = await cur.fetchone()
    # Only log if the row actually existed - avoid ghost audit entries for secrets already deleted by the trigger or a prior sweep
    if deleted:
        await audit_service.log(
            "secret_deleted",
            secret_id=secret_id,
            metadata={"reason": "ttl_expired", "source": "redis_event"},
        )

async def _fallback_sweep() -> int:
    # Hard-delete expired or fully-viewed secrets / inactive users / revoked or expired sessions. Returns count of deleted rows.
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            # Expired or fully-viewed secrets
            await cur.execute(
                """
                DELETE FROM secrets
                WHERE expires_at < NOW() OR view_count >= max_views
                RETURNING id
                """
            )
            deleted_secrets = [row[0] for row in await cur.fetchall()]
            # Inactive users past their delete_after date
            await cur.execute(
                """
                DELETE FROM users
                WHERE is_active = FALSE AND delete_after <= NOW()
                RETURNING id
                """
            )
            deleted_users = [row[0] for row in await cur.fetchall()]
            # Revoked or expired sessions
            await cur.execute(
                """
                DELETE FROM sessions
                WHERE revoked = TRUE OR expires_at <= NOW()
                RETURNING id
                """
            )
            deleted_sessions = len(await cur.fetchall())
    # Log each deleted secret individually so secret_id is captured per row
    for secret_id in deleted_secrets:
        await audit_service.log(
            "secret_deleted",
            secret_id=str(secret_id),
            metadata={"reason": "ttl_expired/max_views_achieved", "source": "fallback_sweep"},
        )
    # Log each deleted user individually so user_id is captured per row
    for user_id in deleted_users:
        await audit_service.log(
            "user_removed",
            actor_id=str(user_id),
            metadata={"reason": "user_inactive", "source": "fallback_sweep"},
        )
    total = len (deleted_secrets) + len(deleted_users) + deleted_sessions
    return total

async def _listen_for_expirations() -> None:
    # Subscribe to expired-key events on the SAME logical DB as REDIS_URL (not always 0).
    redis = get_redis()
    channel = f"__keyevent@{0}__:expired"
    pubsub = redis.pubsub()
    await pubsub.psubscribe(channel)
    print(f"[CLEANUP] Subscribed to Redis keyspace channel {channel} (phantom:expiry:* -> DELETE secret)")
    async for message in pubsub.listen():
        if message["type"] != "pmessage":
            continue
        key: str = message["data"]
        if not key.startswith(REDIS_EXPIRY_PREFIX):
            continue
        secret_id = key.removeprefix(REDIS_EXPIRY_PREFIX)
        try:
            await _delete_secret(secret_id)
            print(f"[CLEANUP] Deleted secret {secret_id} via Redis event")
        except Exception as exc:
            print(f"[CLEANUP ERROR] Failed to delete {secret_id}: {exc}")

async def _fallback_loop() -> None:
    # Periodic sweep : runs every 10 minutes regardless of Redis events.
    while True:
        await asyncio.sleep(FALLBACK_SWEEP_INTERVAL)
        try:
            deleted = await _fallback_sweep()
            if deleted:
                print(f"[CLEANUP] Fallback sweep removed {deleted} secret(s)")
        except Exception as exc:
            print(f"[CLEANUP ERROR] Fallback sweep failed: {exc}")

async def expiry_worker() -> None:
    try:
        get_redis()
    except RuntimeError:
        print("[CLEANUP] Redis unavailable; running DB fallback sweep only")
        await _fallback_loop()
        return
    await asyncio.gather(
        _listen_for_expirations(),
        _fallback_loop(),
    )