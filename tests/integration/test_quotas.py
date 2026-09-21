import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.services import quota_service


async def _create_user(db_pool, *, max_secrets=1, max_bytes=10):
    user_id = uuid4()
    async with db_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO users(id, email, username, password_hash, is_verified)
                VALUES (%s, %s, %s, 'hash', TRUE)
                """,
                (user_id, f"{user_id}@example.com", f"u_{user_id.hex[:12]}"),
            )
            await cur.execute(
                """
                INSERT INTO user_quotas(user_id, max_active_secrets, max_file_bytes)
                VALUES (%s, %s, %s)
                """,
                (user_id, max_secrets, max_bytes),
            )
    return str(user_id)


@pytest.mark.asyncio
async def test_concurrent_reservations_cannot_oversubscribe_secret_quota(
    db_pool, redis_client, monkeypatch,
):
    monkeypatch.setattr(quota_service, "get_pool", lambda: db_pool)
    monkeypatch.setattr(quota_service, "get_redis", lambda: redis_client)
    user_id = await _create_user(db_pool)

    async def attempt():
        try:
            return await quota_service.reserve(user_id, secrets=1)
        except HTTPException as exc:
            return exc

    results = await asyncio.gather(attempt(), attempt())
    reservations = [result for result in results if isinstance(result, quota_service.Reservation)]
    errors = [result for result in results if isinstance(result, HTTPException)]
    assert len(reservations) == 1
    assert len(errors) == 1
    assert errors[0].status_code == 409
    assert errors[0].detail["quota"] == "MAX_ACTIVE_SECRETS"
    await quota_service.release(reservations[0])


@pytest.mark.asyncio
async def test_file_byte_reservation_is_atomic_and_releasable(
    db_pool, redis_client, monkeypatch,
):
    monkeypatch.setattr(quota_service, "get_pool", lambda: db_pool)
    monkeypatch.setattr(quota_service, "get_redis", lambda: redis_client)
    user_id = await _create_user(db_pool, max_bytes=10)

    reservation = await quota_service.reserve(user_id, file_bytes=8)
    # Read-side reconciliation must retain in-flight reservations.
    usage = await quota_service.usage(user_id)
    assert usage["file_bytes"] == 8
    with pytest.raises(HTTPException) as exc:
        await quota_service.reserve(user_id, file_bytes=3)
    assert exc.value.detail["quota"] == "MAX_FILE_STORAGE"

    await quota_service.release(reservation)
    replacement = await quota_service.reserve(user_id, file_bytes=10)
    await quota_service.release(replacement)
