"""Version creation, history, and restore routes for text secrets."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.config import get_settings
from app.core.permissions import require_owns_secret, require_user
from app.helper import decrypt_content, encrypt_content
from app.routers import secrets
from app.schemas_versioning import (
    SecretUpdate,
    SecretUpdateResponse,
    SecretVersionItem,
    SecretVersionList,
)
from app.services import audit_service
from app.services.key_service import create_version_key, get_dek_for_secret

settings = get_settings()
router = APIRouter(tags=["secret versions"])


def _get_pool():
    # Resolve through the parent router to retain its test injection point.
    return secrets.get_pool()


async def _insert_text_version(
    conn,
    secret_id: str,
    version: int,
    plaintext: str,
    actor_id: str,
    change_note: str | None,
) -> int:
    dek, key_version = await create_version_key(conn, secret_id)
    ciphertext, nonce = encrypt_content(plaintext, dek)
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO secret_versions(
                secret_id, version, content, nonce, key_version,
                plaintext_size, created_by, change_note
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                secret_id,
                version,
                ciphertext,
                nonce,
                key_version,
                len(plaintext.encode()),
                actor_id,
                change_note,
            ),
        )
        await cur.execute(
            """
            UPDATE secrets SET content = %s, nonce = %s, current_version = %s,
                               updated_at = clock_timestamp()
            WHERE id = %s
            """,
            (ciphertext, nonce, version, secret_id),
        )
    return key_version


@router.put("/{secret_id}", response_model=SecretUpdateResponse)
async def update_secret(
    secret_id: UUID,
    body: SecretUpdate,
    request: Request,
    current_user: dict = Depends(require_user),
):
    async with _get_pool().connection() as conn, conn.transaction():
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT owner_id, current_version, payload_type, expires_at
                FROM secrets WHERE id = %s FOR UPDATE
                """,
                (secret_id,),
            )
            row = await cur.fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
        require_owns_secret(str(row[0]) if row[0] else None, current_user)
        if row[3] <= datetime.now(timezone.utc):
            raise HTTPException(status.HTTP_410_GONE, "Secret has expired")
        if row[2] != "text":
            raise HTTPException(status.HTTP_409_CONFLICT, "Use the file update endpoint")
        if row[1] != body.expected_version:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={"error_code": "VERSION_CONFLICT", "current_version": row[1]},
            )
        if row[1] >= settings.MAX_SECRET_VERSIONS:
            raise HTTPException(status.HTTP_409_CONFLICT, "Maximum versions reached")
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT key_version FROM secret_versions
                WHERE secret_id = %s AND version = %s
                """,
                (secret_id, row[1]),
            )
            current_key = await cur.fetchone()
        if not current_key or current_key[0] is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Server-side updates are unavailable for client-encrypted secrets",
            )
        new_version = row[1] + 1
        key_version = await _insert_text_version(
            conn,
            str(secret_id),
            new_version,
            body.content,
            current_user["id"],
            body.change_note,
        )
        await audit_service.log(
            "secret_updated",
            conn=conn,
            actor_id=UUID(current_user["id"]),
            actor_ip=request.state.client_ip,
            secret_id=secret_id,
            metadata={
                "from_version": row[1],
                "to_version": new_version,
                "key_version": key_version,
            },
        )
    return SecretUpdateResponse(
        secret_id=secret_id,
        version=new_version,
        updated_at=datetime.now(timezone.utc),
    )


@router.get("/{secret_id}/versions", response_model=SecretVersionList)
async def list_secret_versions(
    secret_id: UUID,
    current_user: dict = Depends(require_user),
):
    async with _get_pool().connection() as conn, conn.cursor() as cur:
        await cur.execute(
            "SELECT owner_id, current_version FROM secrets WHERE id = %s",
            (secret_id,),
        )
        secret = await cur.fetchone()
        if not secret:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
        require_owns_secret(str(secret[0]) if secret[0] else None, current_user)
        await cur.execute(
            """
                SELECT version, plaintext_size, created_by,
                       change_note, created_at
                FROM secret_versions WHERE secret_id = %s ORDER BY version DESC
                """,
            (secret_id,),
        )
        rows = await cur.fetchall()
    return SecretVersionList(
        current_version=secret[1],
        items=[
            SecretVersionItem(
                version=row[0],
                plaintext_size=row[1],
                created_by=row[2],
                change_note=row[3],
                created_at=row[4],
                is_current=row[0] == secret[1],
            )
            for row in rows
        ],
    )


@router.post("/{secret_id}/versions/{version}/restore", response_model=SecretUpdateResponse)
async def restore_secret_version(
    secret_id: UUID,
    version: int,
    request: Request,
    current_user: dict = Depends(require_user),
):
    async with _get_pool().connection() as conn, conn.transaction():
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT owner_id, current_version FROM secrets WHERE id = %s FOR UPDATE",
                (secret_id,),
            )
            secret = await cur.fetchone()
            if not secret:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
            require_owns_secret(str(secret[0]) if secret[0] else None, current_user)
            if secret[1] >= settings.MAX_SECRET_VERSIONS:
                raise HTTPException(status.HTTP_409_CONFLICT, "Maximum versions reached")
            await cur.execute(
                """
                SELECT payload_type, content, nonce, key_version
                FROM secret_versions WHERE secret_id = %s AND version = %s
                """,
                (secret_id, version),
            )
            old = await cur.fetchone()
        if not old:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret version not found")
        if old[0] != "text" or old[3] is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Only server-encrypted text versions can be restored",
            )
        dek = await get_dek_for_secret(conn, str(secret_id), old[3])
        plaintext = decrypt_content(old[1], old[2], dek)
        new_version = secret[1] + 1
        await _insert_text_version(
            conn,
            str(secret_id),
            new_version,
            plaintext,
            current_user["id"],
            f"Restored version {version}",
        )
        await audit_service.log(
            "secret_version_restored",
            conn=conn,
            actor_id=UUID(current_user["id"]),
            actor_ip=request.state.client_ip,
            secret_id=secret_id,
            metadata={"restored_version": version, "new_version": new_version},
        )
    return SecretUpdateResponse(
        secret_id=secret_id,
        version=new_version,
        updated_at=datetime.now(timezone.utc),
    )
