"""
cleanup_service.py - Expiry driven by Redis keyspace notifications.

Flow:
  1. On secret creation, schedule_expiry() sets a Redis key with TTL.
  2. When that key expires, Redis emits a keyspace event.
  3. expiry_worker() is subscribed to those events and deletes the
     specific secret from PostgreSQL immediately.
  4. A fallback DB sweep runs every 10 minutes to catch any secrets
     missed during Redis downtime.

Distributed locking (multi-instance safety):
  - _delete_secret() acquires a per-secret Redis lock (SET NX EX) before
    touching PostgreSQL. Only one instance wins; others see the lock and
    skip silently — the winner handles deletion.
  - _fallback_sweep() acquires a single global lock before running. If
    another instance already holds it, this instance skips that cycle
    entirely — no duplicate deletions, no race on bulk cleanup.
"""
import asyncio
import uuid
from datetime import datetime, timezone

from app.core.database import get_pool
from app.core.redis_client import get_redis
from app.services import audit_service, quota_service, storage_service

REDIS_EXPIRY_PREFIX = "phantom:expiry:"
REDIS_LOCK_PREFIX   = "phantom:lock:"          # per-secret deletion lock
REDIS_SWEEP_LOCK    = "phantom:lock:sweep"      # global fallback-sweep lock

FALLBACK_SWEEP_INTERVAL = 600   # seconds
SECRET_LOCK_TTL         = 30    # seconds - safely covers one DB delete round-trip
SWEEP_LOCK_TTL          = 120   # seconds - covers the full sweep even under load


async def schedule_expiry(secret_id: str, ttl_seconds: int) -> None:
    """Set a Redis sentinel key that expires after ttl_seconds."""
    redis = get_redis()
    key = f"{REDIS_EXPIRY_PREFIX}{secret_id}"
    await redis.setex(key, ttl_seconds, secret_id)


async def acquire_lock(lock_key: str, ttl: int) -> str | None:
    """
    Try to acquire a Redis lock via SET NX EX.

    Returns the lock token (a UUID) if acquired, None if another instance
    already holds the lock. The token must be passed to _release_lock() to
    prevent a slow instance from releasing a lock it no longer owns.
    """
    redis = get_redis()
    token = str(uuid.uuid4())
    acquired = await redis.set(lock_key, token, nx=True, ex=ttl)
    return token if acquired else None


async def release_lock(lock_key: str, token: str) -> None:
    """
    Release the lock only if we still own it (token matches).

    Uses a Lua script for atomicity - avoids the TOCTOU race condition where we
    check ownership and delete in two separate round-trips.
    """
    redis = get_redis()
    lua = """
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("DEL", KEYS[1])
        else
            return 0
        end
    """
    await redis.eval(lua, 1, lock_key, token) # type: ignore


async def delete_secret(secret_id: str) -> None:
    """
    Delete a single secret from PostgreSQL (redis-event driven).

    Acquires a per-secret distributed lock first so that if multiple
    instances receive the same keyspace event (possible under load),
    only one performs the DELETE. The others see the lock and skip.
    """
    lock_key = f"{REDIS_LOCK_PREFIX}{secret_id}"
    token = await acquire_lock(lock_key, SECRET_LOCK_TTL)
    if token is None:
        # Another instance already handling this secret - skip silently.
        print(f"[CLEANUP] Lock contention on {secret_id} -> skipping (another instance owns it)")
        return
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "DELETE FROM secrets WHERE id = %s RETURNING id, owner_id", (secret_id,)
                )
                deleted = await cur.fetchone()
        # Only audit if the row actually existed - avoids ghost entries for
        # secrets already removed by the PostgreSQL trigger or a prior sweep.
        if deleted:
            await audit_service.log(
                "secret_deleted",
                secret_id=uuid.UUID(secret_id),
                metadata={"reason": "ttl_expired", "source": "redis_event"},
            )
            if deleted[1]:
                await quota_service.reconcile_user(str(deleted[1]))
    finally:
        await release_lock(lock_key, token)


async def fallback_sweep() -> dict:
    """
    Hard-delete expired / fully-viewed secrets, inactive users, and stale
    sessions. Returns total count of deleted rows.

    Acquires a global sweep lock so only one instance runs the bulk DELETE
    at a time. If the lock is held, this cycle is skipped - the lock TTL
    (SWEEP_LOCK_TTL) is set conservatively above the sweep's expected
    runtime so a crashed instance doesn't block forever.
    """
    token = await acquire_lock(REDIS_SWEEP_LOCK, SWEEP_LOCK_TTL)
    if token is None:
        print("[CLEANUP] Sweep lock held by another instance - skipping this cycle")
        return {
            "secrets_deleted":  0,
            "sessions_deleted": 0,
            "users_deleted":    0,
            "ran_at":           datetime.now(timezone.utc),
        }
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                # Expired or fully-viewed secrets
                await cur.execute(
                    """
                    DELETE FROM secrets
                    WHERE expires_at < NOW() OR view_count >= max_views
                    RETURNING id, owner_id
                    """
                )
                deleted_secret_rows = await cur.fetchall()
                deleted_secrets = [row[0] for row in deleted_secret_rows]
                # Inactive users past their delete_after date
                await cur.execute(
                    """
                    DELETE FROM users
                    WHERE is_active = FALSE AND delete_after <= NOW()
                    RETURNING id
                    """
                )
                deleted_users = [row[0] for row in await cur.fetchall()]
                # Tracking and verification challenges have independent lifetimes.
                await cur.execute(
                    "DELETE FROM secret_tracking WHERE retain_until <= clock_timestamp()"
                )
                await cur.execute(
                    "DELETE FROM email_verifications WHERE expires_at <= clock_timestamp()"
                )
                # Revoked or expired sessions
                await cur.execute(
                    """
                    DELETE FROM sessions
                    WHERE revoked = TRUE OR expires_at <= NOW()
                    RETURNING id
                    """
                )
                deleted_sessions = await cur.fetchall()
        # Log per secret so secret_id is captured individually
        for secret_id in deleted_secrets:
            await audit_service.log(
                "secret_deleted",
                secret_id=secret_id,
                metadata={"reason": "ttl_expired/max_views_achieved", "source": "fallback_sweep"},
            )
        for owner_id in {row[1] for row in deleted_secret_rows if row[1]}:
            await quota_service.reconcile_user(str(owner_id))
        await process_storage_cleanup()
        # Log per user so user_id is captured individually
        for user_id in deleted_users:
            await audit_service.log(
                "user_removed",
                actor_id=user_id,
                metadata={"reason": "user_inactive", "source": "fallback_sweep"},
            )
        return {
            "secrets_deleted":  len(deleted_secrets),
            "sessions_deleted": len(deleted_sessions),
            "users_deleted":    len(deleted_users),
            "ran_at":           datetime.now(timezone.utc),
        }
    finally:
        await release_lock(REDIS_SWEEP_LOCK, token)


async def listen_for_expirations() -> None:
    """
    Subscribe to expired-key events on the Redis logical DB from REDIS_URL.
    Fires delete_secret() for each phantom:expiry:* key that expires.
    """
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
            await delete_secret(secret_id)
            print(f"[CLEANUP] Deleted secret {secret_id} via Redis event")
        except Exception as exc:
            print(f"[CLEANUP ERROR] Failed to delete {secret_id}: {exc}")


async def fallback_loop() -> None:
    """Periodic sweep - runs every 10 minutes regardless of Redis events."""
    while True:
        await asyncio.sleep(FALLBACK_SWEEP_INTERVAL)
        try:
            deleted = await fallback_sweep()
            if deleted:
                print(f"[CLEANUP] Fallback sweep removed {deleted} row(s)")
        except Exception as exc:
            print(f"[CLEANUP ERROR] Fallback sweep failed: {exc}")


async def process_storage_cleanup() -> dict:
    """Delete orphaned objects and uploads, then repair affected counters."""
    affected_users: set[str] = set()
    objects_deleted = 0
    pending_deleted = 0
    async with get_pool().connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT id, object_key, user_id FROM object_deletion_outbox
                WHERE processed_at IS NULL AND next_attempt_at <= clock_timestamp()
                ORDER BY id LIMIT 100
                """
            )
            outbox = await cur.fetchall()
            await cur.execute(
                """
                SELECT id, object_key, user_id, reservation_id
                FROM pending_uploads WHERE expires_at <= clock_timestamp()
                ORDER BY expires_at LIMIT 100
                """
            )
            pending = await cur.fetchall()

    for row_id, object_key, user_id in outbox:
        try:
            await storage_service.delete(object_key)
            async with get_pool().connection() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "UPDATE object_deletion_outbox SET processed_at = clock_timestamp(), last_error = NULL WHERE id = %s",
                        (row_id,),
                    )
            objects_deleted += 1
            if user_id:
                affected_users.add(str(user_id))
        except Exception as exc:
            async with get_pool().connection() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        UPDATE object_deletion_outbox SET attempts = attempts + 1,
                            last_error = %s,
                            next_attempt_at = clock_timestamp() +
                                LEAST(3600, POWER(2, LEAST(attempts, 11))) * INTERVAL '1 second'
                        WHERE id = %s
                        """,
                        (str(exc)[:1000], row_id),
                    )

    for pending_id, object_key, user_id, reservation_id in pending:
        try:
            await storage_service.delete(object_key)
            async with get_pool().connection() as conn:
                async with conn.cursor() as cur:
                    await cur.execute("DELETE FROM pending_uploads WHERE id = %s", (pending_id,))
            await quota_service.release(quota_service.Reservation(
                str(reservation_id), str(user_id), 0, 0
            ))
            affected_users.add(str(user_id))
            pending_deleted += 1
        except Exception:
            continue

    try:
        await quota_service.reap_expired_reservations()
    except Exception:
        pass
    for user_id in affected_users:
        try:
            await quota_service.reconcile_user(user_id)
        except Exception:
            pass
    return {"objects_deleted": objects_deleted, "pending_uploads_deleted": pending_deleted}


async def expiry_worker() -> None:
    try:
        get_redis()
    except RuntimeError:
        print("[CLEANUP] Redis unavailable; running DB fallback sweep only")
        await fallback_loop()
        return
    await asyncio.gather(
        listen_for_expirations(),
        fallback_loop(),
    )
