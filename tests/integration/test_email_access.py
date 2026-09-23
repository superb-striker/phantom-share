import asyncio
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.routers import auth as auth_router
from app.routers import secrets as secrets_router
from app.schemas import (
    EmailVerificationRequest,
)
from app.schemas_access import LocationPolicyUpdate
from app.schemas_access import SecretCreateWithPolicy as SecretCreate
from app.schemas_versioning import SecretUpdate


def _request():
    return SimpleNamespace(state=SimpleNamespace(client_ip="127.0.0.1"))


async def _user(db_pool, email, *, verified, role="user"):
    user_id = uuid4()
    username = f"user_{user_id.hex[:12]}"
    async with db_pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO users(id, email, username, password_hash, is_verified, role)
                VALUES (%s, %s, %s, 'hash', %s, %s)
                """,
                (user_id, email, username, verified, role),
            )
    return {
        "id": str(user_id), "email": email, "username": username,
        "role": role, "is_active": True, "is_verified": verified,
    }


@pytest.fixture(autouse=True)
def _services(monkeypatch, db_pool):
    monkeypatch.setattr(secrets_router, "get_pool", lambda: db_pool)
    monkeypatch.setattr(secrets_router.location_policy_service, "get_pool", lambda: db_pool)
    monkeypatch.setattr(auth_router, "get_pool", lambda: db_pool)

    async def no_expiry(*_args, **_kwargs):
        return None

    monkeypatch.setattr(secrets_router.cleanup_service, "schedule_expiry", no_expiry)

    class Reservation:
        pass

    async def reserve(*_args, **_kwargs):
        return Reservation()

    monkeypatch.setattr(secrets_router.quota_service, "reserve", reserve)
    monkeypatch.setattr(secrets_router.quota_service, "commit", no_expiry)
    monkeypatch.setattr(secrets_router.quota_service, "release", no_expiry)


@pytest.mark.asyncio
async def test_restricted_secret_requires_verified_allowed_email_and_retains_history(db_pool):
    owner = await _user(db_pool, "owner@example.com", verified=True)
    allowed = await _user(db_pool, "alice@example.com", verified=True)
    unverified = await _user(db_pool, "bob@example.com", verified=False)
    outsider = await _user(db_pool, "mallory@example.com", verified=True)

    created = await secrets_router.create_secret(
        SecretCreate(
            content="classified",
            max_views=1,
            allowed_emails=[
                "Alice@Example.com", "alice@example.com", "bob@example.com",
            ],
        ),
        _request(),
        owner,
    )
    secret_id = str(created.secret_id)

    async with db_pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT email::text FROM secret_recipients
                WHERE secret_id = %s ORDER BY email
                """,
                (secret_id,),
            )
            assert [row[0] for row in await cur.fetchall()] == [
                "alice@example.com", "bob@example.com",
            ]

    for viewer, expected_status in ((None, 401), (unverified, 403), (outsider, 403)):
        with pytest.raises(HTTPException) as exc:
            await secrets_router._retrieve_secret(
                secret_id, None, created.signed_token,
                _request(), BackgroundTasks(), viewer,
            )
        assert exc.value.status_code == expected_status

    content = await secrets_router._retrieve_secret(
        secret_id, None, created.signed_token,
        _request(), BackgroundTasks(), allowed,
    )
    assert content.content == "classified"
    assert content.views_remaining == 0

    async with db_pool.connection() as conn, conn.cursor() as cur:
            await cur.execute("SELECT 1 FROM secrets WHERE id = %s", (secret_id,))
            assert await cur.fetchone() is None

    history = await secrets_router.secret_views(UUID(secret_id), 1, 20, owner)
    assert history.total == 1
    assert history.items[0].viewer_email == "alice@example.com"
    assert history.items[0].email_verified is True
    assert history.items[0].viewed_at is not None

    with pytest.raises(HTTPException) as exc:
        await secrets_router.secret_views(UUID(secret_id), 1, 20, outsider)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_concurrent_retrieval_records_only_one_success(db_pool):
    owner = await _user(db_pool, "owner2@example.com", verified=True)
    recipient = await _user(db_pool, "reader@example.com", verified=True)
    created = await secrets_router.create_secret(
        SecretCreate(
            content="only once", max_views=1,
            allowed_emails=[recipient["email"]],
        ),
        _request(),
        owner,
    )

    async def retrieve():
        try:
            result = await secrets_router._retrieve_secret(
                str(created.secret_id), None, created.signed_token,
                _request(), BackgroundTasks(), recipient,
            )
            return result.content
        except HTTPException as exc:
            return exc.status_code

    results = await asyncio.gather(retrieve(), retrieve())
    assert sorted(results, key=str) == sorted(["only once", 404], key=str)
    history = await secrets_router.secret_views(created.secret_id, 1, 20, owner)
    assert history.total == 1


@pytest.mark.asyncio
async def test_update_creates_fresh_encrypted_version_and_restore_is_append_only(db_pool):
    owner = await _user(db_pool, "versions@example.com", verified=True)
    created = await secrets_router.create_secret(
        SecretCreate(content="version one", max_views=5), _request(), owner
    )

    updated = await secrets_router.update_secret(
        created.secret_id,
        SecretUpdate(content="version two", expected_version=1, change_note="rotation"),
        _request(), owner,
    )
    assert updated.version == 2
    versions = await secrets_router.list_secret_versions(created.secret_id, owner)
    assert [item.version for item in versions.items] == [2, 1]
    assert versions.items[0].is_current is True

    async with db_pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT v.version, v.content, v.nonce, v.key_version, k.wrapped_dek
                FROM secret_versions v
                JOIN secret_keys k ON k.secret_id = v.secret_id AND k.version = v.key_version
                WHERE v.secret_id = %s ORDER BY v.version
                """,
                (created.secret_id,),
            )
            encrypted_versions = await cur.fetchall()
    assert encrypted_versions[0][1] != encrypted_versions[1][1]
    assert encrypted_versions[0][2] != encrypted_versions[1][2]
    assert encrypted_versions[0][3] != encrypted_versions[1][3]
    assert encrypted_versions[0][4] != encrypted_versions[1][4]

    current = await secrets_router._retrieve_secret(
        str(created.secret_id), None, created.signed_token,
        _request(), BackgroundTasks(), None,
    )
    assert current.content == "version two"
    assert current.version == 2

    restored = await secrets_router.restore_secret_version(
        created.secret_id, 1, _request(), owner
    )
    assert restored.version == 3
    after_restore = await secrets_router._retrieve_secret(
        str(created.secret_id), None, created.signed_token,
        _request(), BackgroundTasks(), None,
    )
    assert after_restore.content == "version one"
    assert after_restore.version == 3


@pytest.mark.asyncio
async def test_cidr_policy_denies_without_consuming_view_and_policy_update_rotates_link(db_pool):
    owner = await _user(db_pool, "network-owner@example.com", verified=True)
    created = await secrets_router.create_secret(
        SecretCreate(content="network secret", max_views=3, allowed_cidrs=["10.0.0.0/8"]),
        _request(), owner,
    )

    with pytest.raises(HTTPException) as denied:
        await secrets_router._retrieve_secret(
            str(created.secret_id), None, created.signed_token,
            _request(), BackgroundTasks(), None,
        )
    assert denied.value.status_code == 403
    assert denied.value.detail["error_code"] == "CIDR_NOT_ALLOWED"
    async with db_pool.connection() as conn:
        assert (await (await conn.execute(
            "SELECT view_count FROM secrets WHERE id = %s", (created.secret_id,)
        )).fetchone())[0] == 0

    changed = await secrets_router.update_location_policy(
        created.secret_id,
        LocationPolicyUpdate(allowed_cidrs=["127.0.0.0/8"]),
        _request(), owner,
    )
    assert changed.policy_version == 2
    with pytest.raises(HTTPException, match="policy"):
        await secrets_router._retrieve_secret(
            str(created.secret_id), None, created.signed_token,
            _request(), BackgroundTasks(), None,
        )
    content = await secrets_router._retrieve_secret(
        str(created.secret_id), None, changed.signed_token,
        _request(), BackgroundTasks(), None,
    )
    assert content.content == "network secret"


@pytest.mark.asyncio
async def test_verification_code_is_hashed_single_use_and_marks_user_verified(
    db_pool, monkeypatch,
):
    user = await _user(db_pool, "verify@example.com", verified=False)
    delivered = {}

    async def capture(email, code):
        delivered.update(email=email, code=code)

    monkeypatch.setattr(auth_router.verification_service, "send_code", capture)
    response = await auth_router.request_email_verification(user)
    assert "sent" in response.message.lower()
    assert delivered["email"] == user["email"]

    async with db_pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT token_hash, token_hash = %s
                FROM email_verifications WHERE user_id = %s
                """,
                (delivered["code"], user["id"]),
            )
            stored_hash, plaintext_was_stored = await cur.fetchone()
            assert plaintext_was_stored is False
            assert len(stored_hash) == 64

    result = await auth_router.confirm_email_verification(
        EmailVerificationRequest(code=delivered["code"]), user
    )
    assert result.message == "Email verified"
    async with db_pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT is_verified FROM users WHERE id = %s", (user["id"],)
            )
            assert (await cur.fetchone())[0] is True

    with pytest.raises(HTTPException) as exc:
        await auth_router.confirm_email_verification(
            EmailVerificationRequest(code=delivered["code"]), user
        )
    assert exc.value.status_code == 400
