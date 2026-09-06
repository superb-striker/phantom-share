import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest

import app.services.cleanup_service as cleanup_service


@pytest.fixture(autouse=True)
def _patch_redis(monkeypatch, redis_client):
    monkeypatch.setattr(cleanup_service, "get_redis", lambda: redis_client)


@pytest.fixture(autouse=True)
def _patch_db(monkeypatch, db_pool):
    monkeypatch.setattr(cleanup_service, "get_pool", lambda: db_pool)


@pytest.fixture(autouse=True)
def _patch_audit(monkeypatch):
    calls = []
    async def fake_log(*args, **kwargs):
        calls.append((args, kwargs))
    monkeypatch.setattr(cleanup_service.audit_service, "log", fake_log)
    return calls


async def _insert_secret(db_pool, expires_at=None, view_count=0, max_views=1, ttl_hours=24):
    secret_id = uuid.uuid4()
    async with db_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO secrets (id, content, ttl_hours, view_count, max_views)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (secret_id, "test-secret-content", ttl_hours, view_count, max_views),
            )
            if expires_at is not None:
                await cur.execute(
                    "UPDATE secrets SET expires_at = %s WHERE id = %s",
                    (expires_at, secret_id),
                )
    return str(secret_id)


async def _secret_exists(db_pool, secret_id) -> bool:
    async with db_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1 FROM secrets WHERE id = %s", (secret_id,))
            return (await cur.fetchone()) is not None


async def _insert_user(db_pool, is_active=True, delete_after=None):
    user_id = uuid.uuid4()
    async with db_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO users (id, email, username, password_hash, is_active)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, f"{user_id}@example.com", f"user_{user_id.hex[:8]}", "hashed", is_active),
            )
            if delete_after is not None:
                await cur.execute(
                    "UPDATE users SET delete_after = %s WHERE id = %s",
                    (delete_after, user_id),
                )
    return str(user_id)


async def _user_exists(db_pool, user_id) -> bool:
    async with db_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1 FROM users WHERE id = %s", (user_id,))
            return (await cur.fetchone()) is not None


async def _insert_session(db_pool, user_id, revoked=False, expires_at=None):
    session_id = uuid.uuid4()
    if expires_at is None:
        expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    async with db_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO sessions (id, user_id, refresh_token_hash, expires_at, revoked)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (session_id, user_id, f"hash-{session_id}", expires_at, revoked),
            )
    return str(session_id)


async def _session_exists(db_pool, session_id) -> bool:
    async with db_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1 FROM sessions WHERE id = %s", (session_id,))
            return (await cur.fetchone()) is not None


class TestDistributedLock:
    @pytest.mark.asyncio
    async def test_acquire_lock_succeeds_when_free(self):
        token = await cleanup_service.acquire_lock("test:lock:a", ttl=10)
        assert token is not None

    @pytest.mark.asyncio
    async def test_second_acquire_fails_while_held(self):
        token1 = await cleanup_service.acquire_lock("test:lock:b", ttl=10)
        token2 = await cleanup_service.acquire_lock("test:lock:b", ttl=10)
        assert token1 is not None
        assert token2 is None

    @pytest.mark.asyncio
    async def test_lock_available_again_after_release(self):
        token1 = await cleanup_service.acquire_lock("test:lock:c", ttl=10)
        await cleanup_service.release_lock("test:lock:c", token1)
        token2 = await cleanup_service.acquire_lock("test:lock:c", ttl=10)
        assert token2 is not None

    @pytest.mark.asyncio
    async def test_release_with_wrong_token_does_not_release(self):
        """
        Guards the TOCTOU fix in release_lock: a slow/late instance
        holding a stale token must not be able to release a lock a
        newer owner currently holds.
        """
        await cleanup_service.acquire_lock("test:lock:d", ttl=10)
        await cleanup_service.release_lock("test:lock:d", "not-the-real-token")
        token2 = await cleanup_service.acquire_lock("test:lock:d", ttl=10)
        assert token2 is None  # still held by the original owner

    @pytest.mark.asyncio
    async def test_only_one_of_many_concurrent_acquirers_wins(self):
        """
        The core distributed-lock guarantee, stress-tested directly:
        fire 20 concurrent acquire attempts at the same key and assert
        exactly one gets a token.
        """
        tokens = await asyncio.gather(
            *[cleanup_service.acquire_lock("test:lock:race", ttl=10) for _ in range(20)]
        )
        winners = [t for t in tokens if t is not None]
        assert len(winners) == 1


class TestDeleteSecretUnderConcurrency:
    @pytest.mark.asyncio
    async def test_delete_secret_removes_the_row(self, db_pool):
        secret_id = await _insert_secret(db_pool)
        await cleanup_service.delete_secret(secret_id)
        assert not await _secret_exists(db_pool, secret_id)

    @pytest.mark.asyncio
    async def test_delete_secret_on_already_deleted_id_is_a_noop(self):
        # Simulates a second instance receiving the same keyspace event
        # after the first already deleted the row - should not raise.
        fake_id = str(uuid.uuid4())
        await cleanup_service.delete_secret(fake_id)

    @pytest.mark.asyncio
    async def test_concurrent_delete_secret_calls_delete_exactly_once(self, db_pool, _patch_audit):
        """
        spins up 10 concurrent 'instances' racing to delete
        the same secret_id (as could happen if multiple API replicas
        all subscribe to the same Redis keyspace channel) and asserts
        the row is deleted exactly once, with exactly one audit log
        entry - not ten.
        """
        secret_id = await _insert_secret(db_pool)
        await asyncio.gather(*[cleanup_service.delete_secret(secret_id) for _ in range(10)])
        assert not await _secret_exists(db_pool, secret_id)
        assert len(_patch_audit) == 1


class TestFallbackSweep:
    @pytest.mark.asyncio
    async def test_sweep_deletes_expired_secrets(self, db_pool):
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        expired_id = await _insert_secret(db_pool, expires_at=past)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        alive_id = await _insert_secret(db_pool, expires_at=future)

        result = await cleanup_service.fallback_sweep()

        assert result["secrets_deleted"] >= 1
        assert not await _secret_exists(db_pool, expired_id)
        assert await _secret_exists(db_pool, alive_id)

    @pytest.mark.asyncio
    async def test_sweep_deletes_secrets_at_max_views(self, db_pool):
        """
        Inserted directly at view_count == max_views (not via an UPDATE),
        so the delete_secret_if_fully_viewed DB trigger - which only
        fires AFTER UPDATE OF view_count - never runs. This isolates
        fallback_sweep's own catch of the same condition as a genuine
        backstop, rather than accidentally testing the DB trigger instead.
        """
        maxed_id = await _insert_secret(db_pool, view_count=3, max_views=3)
        await cleanup_service.fallback_sweep()
        assert not await _secret_exists(db_pool, maxed_id)

    @pytest.mark.asyncio
    async def test_sweep_deletes_inactive_users_past_delete_after(self, db_pool):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        stale_id = await _insert_user(db_pool, is_active=False, delete_after=past)
        future = datetime.now(timezone.utc) + timedelta(days=1)
        pending_id = await _insert_user(db_pool, is_active=False, delete_after=future)
        active_id = await _insert_user(db_pool, is_active=True)

        result = await cleanup_service.fallback_sweep()

        assert result["users_deleted"] >= 1
        assert not await _user_exists(db_pool, stale_id)
        assert await _user_exists(db_pool, pending_id)
        assert await _user_exists(db_pool, active_id)

    @pytest.mark.asyncio
    async def test_sweep_deletes_revoked_and_expired_sessions(self, db_pool):
        user_id = await _insert_user(db_pool)
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        expired_session_id = await _insert_session(db_pool, user_id, expires_at=past)
        revoked_session_id = await _insert_session(db_pool, user_id, revoked=True)
        active_session_id = await _insert_session(db_pool, user_id)

        result = await cleanup_service.fallback_sweep()

        assert result["sessions_deleted"] >= 2
        assert not await _session_exists(db_pool, expired_session_id)
        assert not await _session_exists(db_pool, revoked_session_id)
        assert await _session_exists(db_pool, active_session_id)

    @pytest.mark.asyncio
    async def test_only_one_concurrent_sweep_actually_acquires_the_lock(self, monkeypatch):
        """
        Verifies the global sweep lock under real concurrency: spy on
        acquire_lock (rather than comparing zero-vs-zero delete counts,
        which can't distinguish 'skipped' from 'ran and found nothing')
        and assert exactly one of five concurrent fallback_sweep() calls
        actually won the lock.
        """
        original_acquire = cleanup_service.acquire_lock
        results = []

        async def spy_acquire(lock_key, ttl):
            token = await original_acquire(lock_key, ttl)
            results.append(token)
            return token

        monkeypatch.setattr(cleanup_service, "acquire_lock", spy_acquire)
        await asyncio.gather(*[cleanup_service.fallback_sweep() for _ in range(5)])
        winners = [t for t in results if t is not None]
        assert len(winners) == 1
