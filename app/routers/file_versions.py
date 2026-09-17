"""Append-only version updates for file secrets."""

from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)

from app.core.config import get_settings
from app.core.database import get_pool
from app.core.permissions import require_owns_secret, require_user
from app.helper import encrypt_content, generate_dek, wrap_dek
from app.routers.file_support import cleanup_paths, spool_upload, temp_path
from app.services import audit_service, clamav_service, quota_service, storage_service
from app.services.file_crypto import encrypt_file

settings = get_settings()
router = APIRouter(tags=["file versions"])


@router.put("/{secret_id}/file")
async def update_file_secret(
    secret_id: UUID,
    request: Request,
    upload: UploadFile = File(...),
    expected_version: int = Form(..., ge=1),
    change_note: str | None = Form(None, max_length=500),
    current_user: dict = Depends(require_user),
):
    async with get_pool().connection() as conn, conn.cursor() as cur:
        await cur.execute(
            "SELECT owner_id, current_version, payload_type FROM secrets WHERE id = %s",
            (secret_id,),
        )
        secret = await cur.fetchone()
    if not secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
    require_owns_secret(str(secret[0]) if secret[0] else None, current_user)
    if secret[2] != "file":
        raise HTTPException(status.HTTP_409_CONFLICT, "Use the text update endpoint")
    if secret[1] != expected_version:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "error_code": "VERSION_CONFLICT",
                "current_version": secret[1],
            },
        )
    if expected_version >= settings.MAX_SECRET_VERSIONS:
        raise HTTPException(status.HTTP_409_CONFLICT, "Maximum versions reached")

    plaintext = encrypted = None
    object_key = None
    reservation = None
    durable = False
    pending_id = uuid4()
    try:
        plaintext, size = await spool_upload(upload)
        scan_status, scan_detail = await clamav_service.scan(plaintext)
        if scan_status != "clean":
            await audit_service.log_warning(
                "malware_detected",
                actor_id=UUID(current_user["id"]),
                actor_ip=request.state.client_ip,
                metadata={"signature": scan_detail[:200], "size": size},
            )
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Malware detected")
        reservation = await quota_service.reserve(current_user["id"], file_bytes=size)
        version = expected_version + 1
        dek = generate_dek()
        wrapped, dek_nonce = wrap_dek(dek)
        encrypted = temp_path(".encrypted")
        _, digest = encrypt_file(plaintext, encrypted, dek, secret_id, version)
        filename_ciphertext, filename_nonce = encrypt_content(
            upload.filename or "download", dek
        )
        object_key = f"secrets/{secret_id}/versions/{version}/{uuid4()}"
        async with get_pool().connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                    INSERT INTO pending_uploads(
                        id, user_id, secret_id, object_key, reservation_id,
                        plaintext_size, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s,
                              clock_timestamp() + INTERVAL '15 minutes')
                    """,
                (
                    pending_id,
                    current_user["id"],
                    secret_id,
                    object_key,
                    reservation.id,
                    size,
                ),
            )
        encrypted_size = await storage_service.upload(encrypted, object_key)
        async with get_pool().connection() as conn, conn.transaction():
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT owner_id, current_version FROM secrets WHERE id = %s FOR UPDATE",
                    (secret_id,),
                )
                locked = await cur.fetchone()
                if not locked or locked[1] != expected_version:
                    raise HTTPException(
                        status.HTTP_409_CONFLICT,
                        "Secret changed during upload",
                    )
                require_owns_secret(
                    str(locked[0]) if locked[0] else None, current_user
                )
                await cur.execute(
                    "SELECT COALESCE(MAX(version), 0) + 1 FROM secret_keys WHERE secret_id = %s",
                    (secret_id,),
                )
                row = await cur.fetchone()
                if row is None:
                    raise HTTPException(status.HTTP_204_NO_CONTENT, "No key found for this secret")
                key_version = row[0]
                await cur.execute(
                    """
                    INSERT INTO secret_keys(
                        secret_id, wrapped_dek, dek_nonce, version, rotated_at
                    ) VALUES (%s, %s, %s, %s, clock_timestamp())
                    """,
                    (secret_id, wrapped, dek_nonce, key_version),
                )
                await cur.execute(
                    """
                    INSERT INTO secret_versions(
                        secret_id, version, payload_type, key_version, object_key,
                        plaintext_size, encrypted_size, filename_ciphertext,
                        filename_nonce, media_type, content_sha256, clamav_version,
                        scanned_at, created_by, change_note
                    ) VALUES (
                        %s, %s, 'file', %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, clock_timestamp(), %s, %s
                    )
                    """,
                    (
                        secret_id,
                        version,
                        key_version,
                        object_key,
                        size,
                        encrypted_size,
                        filename_ciphertext,
                        filename_nonce,
                        upload.content_type,
                        digest,
                        scan_detail[:200],
                        current_user["id"],
                        change_note,
                    ),
                )
                await cur.execute(
                    """
                    UPDATE secrets
                    SET current_version = %s, updated_at = clock_timestamp()
                    WHERE id = %s
                    """,
                    (version, secret_id),
                )
                await cur.execute(
                    "DELETE FROM pending_uploads WHERE id = %s", (pending_id,)
                )
            await audit_service.log(
                "secret_updated",
                conn=conn,
                actor_id=UUID(current_user["id"]),
                actor_ip=request.state.client_ip,
                secret_id=secret_id,
                metadata={
                    "version": version,
                    "payload_type": "file",
                    "size": size,
                },
            )
        durable = True
        try:
            await quota_service.commit(reservation)
        except Exception:
            await quota_service.reconcile_user(current_user["id"])
        return {"secret_id": secret_id, "version": version, "size": size}
    except Exception:
        if object_key and not durable:
            try:
                await storage_service.delete(object_key)
            except Exception:
                pass
        if reservation and not durable:
            await quota_service.release(reservation)
        raise
    finally:
        cleanup_paths(*(path for path in (plaintext, encrypted) if path is not None))
