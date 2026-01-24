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

REDIS_EXPIRY_PREFIX = "phantom:expiry:"
FALLBACK_SWEEP_INTERVAL = 600  # seconds

async def schedule_expiry(secret_id: str, ttl_seconds: int) -> None:
    # Set a Redis sentinel key that expires after ttl_seconds
    redis = get_redis()
    key = f"{REDIS_EXPIRY_PREFIX}{secret_id}"
    await redis.setex(key, ttl_seconds, secret_id)

async def _delete_secret(secret_id: str) -> None:
    # Hard-delete a single secret from PostgreSQL by ID
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM secrets WHERE id = %s", (secret_id,)
            )

async def _fallback_sweep() -> int:
    """
    Hard-delete all expired or fully-viewed secrets.
    Runs periodically as a safety net for events missed during Redis downtime.
    Returns count of deleted rows.
    """
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE secrets SET deleted_at = NOW()
                WHERE expires_at < NOW() OR view_count >= max_views
                RETURNING id
                """
            )
            deleted = await cur.fetchall()
    return len(deleted)

async def _listen_for_expirations() -> None:
    # Subscribe to Redis expired-key events and delete the corresponding secret from PostgreSQL when its sentinel key fires.
    redis = get_redis()
    pubsub = redis.pubsub()
    await pubsub.psubscribe("__keyevent@0__:expired")
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
    # Entry point called from main.py lifespan. Runs both the Redis subscriber and fallback sweep concurrently.
    await asyncio.gather(
        _listen_for_expirations(),
        _fallback_loop(),
    )