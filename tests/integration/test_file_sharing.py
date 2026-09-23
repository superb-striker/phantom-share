import io
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException, UploadFile
from starlette.datastructures import Headers

from app.routers import files as files_router


async def _user(db_pool):
    user_id = uuid4()
    async with db_pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """
                INSERT INTO users(id, email, username, password_hash, is_verified)
                VALUES (%s, %s, %s, 'hash', TRUE)
                """,
            (user_id, f"{user_id}@example.com", f"u_{user_id.hex[:12]}"),
        )
    return {
        "id": str(user_id), "email": f"{user_id}@example.com",
        "username": f"u_{user_id.hex[:12]}", "role": "user",
        "is_active": True, "is_verified": True,
    }


def _upload(data=b"confidential attachment"):
    return UploadFile(
        io.BytesIO(data), filename="report.txt",
        headers=Headers({"content-type": "text/plain"}),
    )


@pytest.fixture
def file_services(monkeypatch, db_pool):
    monkeypatch.setattr(files_router, "get_pool", lambda: db_pool)
    monkeypatch.setattr(files_router.location_policy_service, "get_pool", lambda: db_pool)
    state = SimpleNamespace(uploaded=None, committed=[], released=[])

    async def reserve(_user_id, **_amount):
        return SimpleNamespace(id=uuid4())

    async def commit(reservation):
        state.committed.append(reservation)

    async def release(reservation):
        state.released.append(reservation)

    async def upload(path, _key):
        state.uploaded = path.read_bytes()
        return len(state.uploaded)

    async def delete(_key):
        return None

    async def no_expiry(*_args):
        return None

    monkeypatch.setattr(files_router.quota_service, "reserve", reserve)
    monkeypatch.setattr(files_router.quota_service, "commit", commit)
    monkeypatch.setattr(files_router.quota_service, "release", release)
    monkeypatch.setattr(files_router.storage_service, "upload", upload)
    monkeypatch.setattr(files_router.storage_service, "delete", delete)
    monkeypatch.setattr(files_router.cleanup_service, "schedule_expiry", no_expiry)
    return state


@pytest.mark.asyncio
async def test_clean_file_is_scanned_then_encrypted_before_storage(
    db_pool, monkeypatch, file_services,
):
    owner = await _user(db_pool)
    scan_calls = []

    async def clean(path):
        scan_calls.append(path.read_bytes())
        return "clean", "ClamAV test OK"

    monkeypatch.setattr(files_router.clamav_service, "scan", clean)
    response = await files_router.create_file_secret(
        SimpleNamespace(state=SimpleNamespace(client_ip="127.0.0.1")),
        _upload(), 24, 2, None, [], "initial file", owner, [], [], "all", True,
    )

    assert scan_calls == [b"confidential attachment"]
    assert b"confidential attachment" not in file_services.uploaded
    assert response["version"] == 1
    assert len(file_services.committed) == 2
    async with db_pool.connection() as conn:
        row = await conn.execute(
            """
            SELECT s.payload_type, s.current_version, v.plaintext_size,
                   v.scanned_at IS NOT NULL, v.object_key IS NOT NULL
            FROM secrets s JOIN secret_versions v ON v.secret_id = s.id
            WHERE s.id = %s
            """,
            (response["secret_id"],),
        )
        assert await row.fetchone() == ("file", 1, 23, True, True)


@pytest.mark.asyncio
async def test_infected_file_never_reaches_object_storage(
    db_pool, monkeypatch, file_services,
):
    owner = await _user(db_pool)

    async def infected(_path):
        return "infected", "stream: Eicar-Signature FOUND"

    monkeypatch.setattr(files_router.clamav_service, "scan", infected)
    with pytest.raises(HTTPException) as exc:
        await files_router.create_file_secret(
            SimpleNamespace(state=SimpleNamespace(client_ip="127.0.0.1")),
            _upload(), 24, 1, None, [], None, owner, [], [], "all", True,
        )
    assert exc.value.status_code == 422
    assert file_services.uploaded is None
    assert len(file_services.released) == 1
