"""Virus-scanned, application-encrypted file secret endpoints."""

from datetime import datetime, timezone
from ipaddress import ip_network
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from pydantic import EmailStr, TypeAdapter, ValidationError

from app.core.config import get_settings
from app.core.database import get_pool
from app.core.permissions import require_user
from app.core.security import (
    create_signed_token,
    get_current_user_optional,
    sha256_hash,
)
from app.helper import decrypt_content, encrypt_content, generate_dek, wrap_dek
from app.routers import file_versions
from app.routers.file_support import (
    cleanup_paths as _cleanup,
)
from app.routers.file_support import (
    spool_upload as _spool,
)
from app.routers.file_support import (
    temp_path as _temp,
)
from app.services import (
    audit_service,
    clamav_service,
    cleanup_service,
    location_policy_service,
    quota_service,
    storage_service,
)
from app.services.file_crypto import decrypt_file, encrypt_file
from app.services.key_service import get_dek_for_secret

settings = get_settings()
router = APIRouter(prefix="/api/secrets", tags=["files"])
_emails = TypeAdapter(list[EmailStr])


def _allowed(values: list[str]) -> list[str]:
    try:
        return list(dict.fromkeys(str(v).lower() for v in _emails.validate_python(values)))
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid allowed email") from exc


async def _authorize(row, secret_id: UUID, password: str | None, current_user: dict | None) -> None:
    password_protected, password_hash, email_restricted = row
    if email_restricted:
        if not current_user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Log in with a verified recipient email")
        if not current_user["is_verified"]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Verify your email before accessing this secret")
        async with get_pool().connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM secret_recipients WHERE secret_id = %s AND email = %s",
                (secret_id, current_user["email"]),
            )
            if not await cur.fetchone():
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Your email is not allowed")
    if password_protected and not password or (password and sha256_hash(password) != password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing password")


@router.post("/files", status_code=status.HTTP_201_CREATED)
async def create_file_secret(
    request: Request,
    upload: UploadFile = File(...),
    ttl_hours: int = Form(24, ge=1, le=168),
    max_views: int = Form(1, ge=1, le=100),
    access_password: str | None = Form(None, min_length=4, max_length=128),
    allowed_email: list[str] = Form(default=[]),
    change_note: str | None = Form(None, max_length=500),
    current_user: dict = Depends(require_user),
    allowed_cidr: list[str] = Form(default=[]),
    allowed_country: list[str] = Form(default=[]),
    location_policy_mode: str = Form("all", pattern="^(all|any)$"),
    geoip_fail_closed: bool = Form(True),
):
    secret_reservation = await quota_service.reserve(current_user["id"], secrets=1)
    plaintext = encrypted = None
    object_key = None
    byte_reservation = None
    durable = False
    pending_id = uuid4()
    try:
        plaintext, size = await _spool(upload)
        scan_status, scan_detail = await clamav_service.scan(plaintext)
        if scan_status != "clean":
            await audit_service.log_warning(
                "malware_detected", actor_id=UUID(current_user["id"]),
                actor_ip=request.state.client_ip,
                metadata={"signature": scan_detail[:200], "size": size},
            )
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Malware detected")

        byte_reservation = await quota_service.reserve(current_user["id"], file_bytes=size)
        secret_id = uuid4()
        version = 1
        dek = generate_dek()
        wrapped, dek_nonce = wrap_dek(dek)
        encrypted = _temp(".encrypted")
        _, digest = encrypt_file(plaintext, encrypted, dek, secret_id, version)
        filename_ciphertext, filename_nonce = encrypt_content(upload.filename or "download", dek)
        object_key = f"secrets/{secret_id}/versions/{version}/{uuid4()}"

        async with get_pool().connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO pending_uploads(
                    id, user_id, secret_id, object_key, reservation_id,
                    plaintext_size, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp() + INTERVAL '15 minutes')
                """,
                (pending_id, current_user["id"], secret_id, object_key, byte_reservation.id, size),
            )
        encrypted_size = await storage_service.upload(encrypted, object_key)

        emails = _allowed(allowed_email)
        try:
            cidrs = list(dict.fromkeys(str(ip_network(value, strict=False)) for value in allowed_cidr))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid allowed CIDR") from exc
        countries = list(dict.fromkeys(value.upper() for value in allowed_country))
        if any(len(value) != 2 or not value.isalpha() or not value.isascii() for value in countries):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid country code")
        signed_token = create_signed_token(secret_id, ttl_hours)
        async with get_pool().connection() as conn:
            async with conn.transaction(), conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO secrets(
                        id, content, nonce, password_protected, access_password_hash,
                        ttl_hours, max_views, owner_id, signed_token,
                        email_restricted, payload_type
                    ) VALUES (%s, NULL, NULL, %s, %s, %s, %s, %s, %s, %s, 'file')
                    """,
                    (
                        secret_id, bool(access_password),
                        sha256_hash(access_password) if access_password else None,
                        ttl_hours, max_views, current_user["id"], signed_token, bool(emails),
                    ),
                )
                await cur.execute(
                    """
                    INSERT INTO secret_keys(secret_id, wrapped_dek, dek_nonce, version)
                    VALUES (%s, %s, %s, 1)
                    """,
                    (secret_id, wrapped, dek_nonce),
                )
                await cur.execute(
                    """
                    INSERT INTO secret_versions(
                        secret_id, version, payload_type, key_version, object_key,
                        plaintext_size, encrypted_size, filename_ciphertext,
                        filename_nonce, media_type, content_sha256, clamav_version,
                        scanned_at, created_by, change_note
                    ) VALUES (%s, 1, 'file', 1, %s, %s, %s, %s, %s, %s, %s, %s,
                                clock_timestamp(), %s, %s)
                    """,
                    (
                        secret_id, object_key, size, encrypted_size,
                        filename_ciphertext, filename_nonce,
                        upload.content_type, digest, scan_detail[:200],
                        current_user["id"], change_note,
                    ),
                )
                if emails:
                    await cur.executemany(
                        "INSERT INTO secret_recipients(secret_id, email) VALUES (%s, %s)",
                        [(secret_id, email) for email in emails],
                    )
                await cur.execute(
                    """
                    INSERT INTO secret_access_policies(
                        secret_id, allowed_cidrs, allowed_countries,
                        location_policy_mode, geoip_fail_closed
                    ) VALUES (%s, %s::cidr[], %s::char(2)[], %s, %s)
                    """,
                    (secret_id, cidrs, countries, location_policy_mode, geoip_fail_closed),
                )
                await cur.execute(
                    """
                    INSERT INTO secret_tracking(secret_id, owner_id, retain_until)
                    SELECT id, owner_id, expires_at + %s * INTERVAL '1 day'
                    FROM secrets WHERE id = %s
                    """,
                    (settings.VIEW_HISTORY_RETENTION_DAYS, secret_id),
                )
                await cur.execute("DELETE FROM pending_uploads WHERE id = %s", (pending_id,))
            await audit_service.log(
                "file_uploaded", conn=conn, actor_id=UUID(current_user["id"]),
                actor_ip=request.state.client_ip, secret_id=secret_id,
                metadata={"version": 1, "size": size},
            )
        durable = True
        try:
            await quota_service.commit(secret_reservation)
            await quota_service.commit(byte_reservation)
        except Exception:
            await quota_service.reconcile_user(current_user["id"])
        try:
            await cleanup_service.schedule_expiry(str(secret_id), ttl_hours * 3600)
        except Exception:
            pass
        return {
            "secret_id": secret_id,
            "share_url": f"{settings.BASE_URL}/api/secrets/{secret_id}/file?token={signed_token}",
            "signed_token": signed_token,
            "version": 1,
            "size": size,
        }
    except Exception:
        if object_key and not durable:
            try:
                await storage_service.delete(object_key)
            except Exception:
                pass
        if byte_reservation and not durable:
            await quota_service.release(byte_reservation)
        if not durable:
            await quota_service.release(secret_reservation)
        raise
    finally:
        _cleanup(*(p for p in (plaintext, encrypted) if p is not None))


@router.get("/{secret_id}/file")
async def download_file_secret(
    secret_id: UUID,
    background_tasks: BackgroundTasks,
    request: Request,
    token: str | None = Query(None),
    access_password: str | None = Query(None),
    current_user: dict | None = Depends(get_current_user_optional),
):
    policy_version = await location_policy_service.authorize(
        secret_id, token, request.state.client_ip
    )
    async with get_pool().connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """
            SELECT password_protected, access_password_hash, email_restricted,
                    s.current_version, s.expires_at, s.view_count, s.max_views,
                    p.policy_version
            FROM secrets s JOIN secret_access_policies p ON p.secret_id = s.id
            WHERE s.id = %s AND s.payload_type = 'file'
            """,
            (secret_id,),
        )
        secret = await cur.fetchone()
        if not secret:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "File secret not found")
    await _authorize(secret[:3], secret_id, access_password, current_user)
    if secret[7] != policy_version:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Share token policy is no longer current")
    if secret[4] <= datetime.now(timezone.utc) or secret[5] >= secret[6]:
        raise HTTPException(status.HTTP_410_GONE, "Secret is no longer available")

    encrypted = _temp(".encrypted")
    plaintext = _temp(".download")
    try:
        async with get_pool().connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                SELECT object_key FROM secret_versions
                WHERE secret_id = %s AND version = %s
                """,
                (secret_id, secret[3]),
            )
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Did not find a file for provided secret id and version")
            object_key = row[0]
            
        await storage_service.download(object_key, encrypted)

        async with get_pool().connection() as conn:
            async with conn.transaction():
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        SELECT password_protected, access_password_hash, email_restricted,
                               s.current_version, s.view_count, s.max_views, p.policy_version
                        FROM secrets s JOIN secret_access_policies p ON p.secret_id = s.id
                        WHERE s.id = %s FOR UPDATE OF s
                        """,
                        (secret_id,),
                    )
                    locked = await cur.fetchone()
                    if not locked or locked[3] != secret[3]:
                        raise HTTPException(status.HTTP_409_CONFLICT, "Secret changed; retry download")
                    if locked[6] != policy_version:
                        raise HTTPException(status.HTTP_403_FORBIDDEN, "Share token policy is no longer current")
                    if locked[4] >= locked[5]:
                        raise HTTPException(status.HTTP_410_GONE, "Secret is no longer available")
                    await cur.execute(
                        """
                        SELECT key_version, filename_ciphertext, filename_nonce, media_type
                        FROM secret_versions WHERE secret_id = %s AND version = %s
                        """,
                        (secret_id, locked[3]),
                    )
                    version_row = await cur.fetchone()
                if not version_row:
                    raise HTTPException(status.HTTP_404_NOT_FOUND, "Key not found for the secret version")
                dek = await get_dek_for_secret(conn, str(secret_id), version_row[0])
                filename = decrypt_content(version_row[1], version_row[2], dek)
                # Authenticate the complete object before consuming a view. A
                # corrupt object therefore cannot burn the recipient's access.
                decrypt_file(encrypted, plaintext, dek, secret_id, secret[3])
                new_count = locked[4] + 1
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        INSERT INTO secret_views(
                            secret_id, viewer_id, viewer_email, email_verified, content_version
                        ) SELECT secret_id, %s, %s, %s, %s
                          FROM secret_tracking WHERE secret_id = %s
                        """,
                        (
                            current_user["id"] if current_user else None,
                            current_user["email"] if current_user else None,
                            current_user["is_verified"] if current_user else False,
                            locked[3], secret_id,
                        ),
                    )
                    await cur.execute(
                        "UPDATE secrets SET view_count = %s, viewed = %s WHERE id = %s",
                        (new_count, new_count >= locked[5], secret_id),
                    )
                await audit_service.log(
                    "secret_viewed", conn=conn,
                    actor_id=UUID(current_user["id"]) if current_user else None,
                    actor_ip=request.state.client_ip, secret_id=secret_id,
                    metadata={"version": locked[3], "payload_type": "file"},
                )
    except Exception:
        _cleanup(encrypted, plaintext)
        raise

    _cleanup(encrypted)
    background_tasks.add_task(_cleanup, plaintext)
    return FileResponse(
        plaintext, filename=Path(filename).name or "download",
        media_type=version_row[3] or "application/octet-stream",
        background=background_tasks,
    )

router.include_router(file_versions.router)

# Compatibility export for callers that imported the handler from this module.
update_file_secret = file_versions.update_file_secret
