"""
routers/secrets.py – /api/secrets/* endpoints.

  POST   /api/secrets                    – create secret (auth optional)
  POST   /api/secrets/{id}               – retrieve & burn (programmatic, password in body)
  GET    /api/secrets/{id}               – retrieve & burn (browser-friendly, password in query)
  GET    /api/secrets/{id}/info          – metadata only, no auth required
  DELETE /api/secrets/{id}               – hard-delete (owner or admin)
  GET    /api/secrets                    – list own secrets (paginated + filtered)
  POST   /api/secrets/{id}/rotate-key    – rotate encryption key (owner only)
"""
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID
from psycopg import sql
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status

from app.core.config import get_settings
from app.core.database import get_pool
from app.core.permissions import require_owns_secret, require_user
from app.core.security import (
    create_signed_token,
    get_current_user_optional,
    sha256_hash,
    verify_signed_token,
)
from app.core.rate_limit import limiter
from app.helper import (
    decrypt_content,
    encrypt_content,
    generate_dek,
    generate_qr_code,
    validate_client_encrypted,
    wrap_dek,
)
from app.schemas import (
    KeyRotateResponse,
    SecretContent,
    SecretCreate,
    SecretCreateResponse,
    SecretInfo,
    SecretListItem,
    SecretListResponse,
    SecretRetrieveRequest,
)
from app.services import audit_service, cleanup_service, notification_service
from app.services.key_service import get_dek_for_secret, rotate_key

settings = get_settings()
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/secrets", tags=["secrets"])

async def _insert_secret(conn, content: str, nonce: Optional[str], body: SecretCreate, owner_id) -> str:
    """Insert a secrets row and return its UUID as a string."""
    pw_hash = sha256_hash(body.access_password) if body.password_protected and body.access_password else None
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO secrets (
                content, nonce, password_protected, access_password_hash,
                ttl_hours, max_views, notify_on_view,
                notify_email, webhook_url, owner_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                content, nonce,
                body.password_protected, pw_hash,
                body.ttl_hours, body.max_views,
                body.notify_on_view,
                str(body.notify_email)  if body.notify_email  else None,
                str(body.webhook_url)   if body.webhook_url   else None,
                owner_id,
            ),
        )
        row = await cur.fetchone()
    return str(row[0])

# Create
@router.post(
    "",
    response_model=SecretCreateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(limiter(30, 60, scope="secret_create"))],
)
async def create_secret(
    body: SecretCreate,
    request: Request,
    current_user: Optional[dict] = Depends(get_current_user_optional),
):
    owner_id = current_user["id"] if current_user else None
    async with get_pool().connection() as conn:
        async with conn.transaction():
            if body.client_encrypted:
                # Validate that content + nonce are well-formed base64 before storing.
                # Catches malformed input early with a clean 400 instead of a 500 at decrypt time.
                try:
                    validate_client_encrypted(body.content, body.client_nonce) # type: ignore
                except ValueError as exc:
                    raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
                secret_id = await _insert_secret(conn, body.content, body.client_nonce, body, owner_id)
            else:
                dek = generate_dek()
                wrapped_dek, dek_nonce      = wrap_dek(dek)
                encrypted_content, nonce    = encrypt_content(body.content, dek)
                secret_id = await _insert_secret(conn, encrypted_content, nonce, body, owner_id)
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        INSERT INTO secret_keys (secret_id, wrapped_dek, dek_nonce, version)
                        VALUES (%s, %s, %s, 1)
                        """,
                        (secret_id, wrapped_dek, dek_nonce),
                    )
            signed_token = create_signed_token(UUID(secret_id), body.ttl_hours)
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE secrets SET signed_token = %s WHERE id = %s",
                    (signed_token, secret_id),
                )
            # Audit inside the transaction so it rolls back on failure
            await audit_service.log(
                "secret_created",
                conn=conn,
                actor_id=UUID(owner_id) if owner_id else None,
                actor_ip=request.state.client_ip,
                secret_id=UUID(secret_id),
            )
    share_url = f"{settings.BASE_URL}/api/secrets/{secret_id}?token={signed_token}"
    # Schedule Redis expiry sentinel - non-critical, swallow errors gracefully
    try:
        await cleanup_service.schedule_expiry(secret_id, body.ttl_hours * 3600)
    except Exception:
        pass
    qr = generate_qr_code(share_url)
    # Fetch expires_at that was computed by the DB trigger
    async with get_pool().connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT expires_at FROM secrets WHERE id = %s", (secret_id,))
            row = await cur.fetchone()
    expires_at = row[0] if row else None
    return SecretCreateResponse(
        secret_id=UUID(secret_id),
        share_url=share_url,
        signed_token=signed_token,
        expires_at=expires_at, # type: ignore
        qr_code=qr,
    )

# Retrieve – shared implementation
async def _retrieve_secret(
    secret_id: str,
    access_password: Optional[str],
    token: Optional[str],
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Optional[dict],
) -> SecretContent:
    """
    Core retrieval logic shared by both the browser (GET) and programmatic (POST) endpoints.

    Steps:
      1. Validate signed share token if provided.
      2. Fetch secret row and enforce expiry / view-count guards.
      3. Enforce access password if set.
      4. Decrypt (server-side) or return opaque ciphertext (client-side).
      5. Increment view_count - the DB trigger deletes the row if max_views is reached.
      6. Emit audit log + optional notification.
    """
    if token:
        verified_id = verify_signed_token(token)
        try:
            if UUID(verified_id) != UUID(secret_id):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Share token does not match this secret")
        except ValueError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid share token") from exc
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT id, content, nonce, password_protected, access_password_hash,
                       view_count, max_views, expires_at, created_at,
                       notify_on_view, notify_email, webhook_url
                FROM secrets
                WHERE id = %s
                """,
                (secret_id,),
            )
            row = await cur.fetchone()
        if not row:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found or has expired")
        (
            _,
            enc_content, nonce,
            pw_protected, pw_hash,
            view_count, max_views,
            expires_at, created_at,
            notify_on_view, notify_email, webhook_url,
        ) = row
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status.HTTP_410_GONE, "Secret has expired")
        if view_count >= max_views:
            raise HTTPException(status.HTTP_410_GONE, "Secret has reached its maximum view count")
        if pw_protected:
            if not access_password:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Password required")
            if sha256_hash(access_password) != pw_hash:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid password")
        # Determine encryption mode
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM secret_keys WHERE secret_id = %s LIMIT 1",
                (secret_id,),
            )
            has_server_key = await cur.fetchone() is not None
        try:
            if has_server_key:
                dek       = await get_dek_for_secret(conn, secret_id)
                plaintext = decrypt_content(enc_content, nonce, dek)
                client_encrypted = False
            else:
                # Client-side encrypted: return ciphertext for the client to decrypt
                plaintext        = enc_content
                client_encrypted = True
        except HTTPException:
            raise
        except ValueError as exc:
            # get_dek_for_secret raises ValueError when no key row exists, and
            # decrypt_content raises it on auth tag mismatch — both are server-side
            # integrity problems, not bad client input.
            logger.error("DEK/decryption failure for secret %s: %s", secret_id, exc)
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to decrypt secret") from exc
        except Exception as exc:
            logger.error("Unexpected decryption error for secret %s: %s", secret_id, exc)
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to decrypt secret") from exc
        new_view_count       = view_count + 1
        is_now_fully_viewed  = new_view_count >= max_views
        await audit_service.log(
            "secret_viewed",
            actor_id=UUID(current_user["id"]) if current_user else None,
            actor_ip=request.state.client_ip,
            secret_id=UUID(secret_id),
            metadata={"view_count": new_view_count, "max_views": max_views},
        )
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE secrets SET view_count = %s, viewed = %s WHERE id = %s",
                (new_view_count, is_now_fully_viewed, secret_id),
            )
        # DB trigger fires here if new_view_count >= max_views and deletes the row
    if notify_on_view:
        background_tasks.add_task(
            notification_service.notify_secret_viewed,
            secret_id, notify_email, webhook_url, request.state.client_ip,
        )
    return SecretContent(
        content=plaintext,
        created_at=created_at,
        expires_at=expires_at,
        views_remaining=max(0, max_views - new_view_count),
        client_encrypted=client_encrypted,
    )

# Retrieve – programmatic (POST, password in body)
@router.post(
    "/{secret_id}",
    response_model=SecretContent,
    dependencies=[Depends(limiter(100, 60, scope="secret_retrieve"))],
)
async def get_secret(
    secret_id: str,
    body: SecretRetrieveRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    token: Optional[str] = Query(default=None),
    current_user: Optional[dict] = Depends(get_current_user_optional),
):
    return await _retrieve_secret(
        secret_id, body.access_password, token, request, background_tasks, current_user
    )


# Retrieve – browser-friendly (GET, password in query param)
@router.get(
    "/{secret_id}",
    response_model=SecretContent,
    dependencies=[Depends(limiter(100, 60, scope="secret_retrieve"))],
)
async def get_secret_browser(
    secret_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    token: Optional[str]           = Query(default=None),
    access_password: Optional[str] = Query(default=None),
    current_user: Optional[dict]   = Depends(get_current_user_optional),
):
    return await _retrieve_secret(
        secret_id, access_password, token, request, background_tasks, current_user
    )


# Info – metadata only (no auth, no content)
@router.get("/{secret_id}/info", response_model=SecretInfo)
async def secret_info(secret_id: str):
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT created_at, expires_at, password_protected,
                       viewed, view_count, max_views
                FROM secrets WHERE id = %s
                """,
                (secret_id,),
            )
            row = await cur.fetchone()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
    return SecretInfo(
        exists=True,
        created_at=row[0],
        expires_at=row[1],
        password_protected=row[2],
        viewed=row[3],
        view_count=row[4],
        max_views=row[5],
    )


# List (owner, paginated + filtered)
@router.get("", response_model=SecretListResponse)
async def list_secrets(
    page:      int           = Query(default=1,  ge=1),
    page_size: int           = Query(default=20, ge=1, le=100),
    viewed:    Optional[bool] = Query(default=None),
    expired:   Optional[bool] = Query(default=None),
    current_user: dict = Depends(require_user),
):
    pool   = get_pool()
    offset = (page - 1) * page_size
    conditions: list[sql.Composable] = [sql.SQL("owner_id = %s")]
    params: list = [current_user["id"]]
    if viewed is not None:
        conditions.append(sql.SQL("viewed = %s"))
        params.append(viewed)
    if expired is True:
        conditions.append(sql.SQL("expires_at < NOW()"))
    elif expired is False:
        conditions.append(sql.SQL("expires_at >= NOW()"))
    where = sql.SQL(" AND ").join(conditions)
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                sql.SQL("SELECT COUNT(*) FROM secrets WHERE {}").format(where),
                params,
            )
            row   = await cur.fetchone()
            total = row[0] if row else 0
            await cur.execute(
                sql.SQL("""
                    SELECT id, created_at, expires_at, viewed, view_count,
                           max_views, password_protected, notify_on_view,
                    FROM secrets
                    WHERE {}
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """).format(where),
                params + [page_size, offset],
            )
            rows = await cur.fetchall()
    items = [
        SecretListItem(
            id=r[0], created_at=r[1], expires_at=r[2],
            viewed=r[3], view_count=r[4], max_views=r[5],
            password_protected=r[6], notify_on_view=r[7],
        )
        for r in rows
    ]
    return SecretListResponse(items=items, total=total, page=page, page_size=page_size)

# Delete
@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(
    secret_id: str,
    request: Request,
    current_user: dict = Depends(require_user),
):
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.transaction():
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT owner_id FROM secrets WHERE id = %s FOR UPDATE",
                    (secret_id,),
                )
                row = await cur.fetchone()
            if not row:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
            require_owns_secret(str(row[0]) if row[0] else None, current_user)
            # Audit before delete so secret_id FK is still valid
            await audit_service.log_critical(
                "secret_deleted",
                actor_id=UUID(current_user["id"]),
                actor_ip=request.state.client_ip,
                secret_id=UUID(secret_id),
                metadata={"reason": "owner_request"},
                conn=conn,
            )
            async with conn.cursor() as cur:
                await cur.execute("DELETE FROM secrets WHERE id = %s", (secret_id,))
                if cur.rowcount == 0:
                    raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")

# Key rotation
@router.post(
    "/{secret_id}/rotate-key",
    response_model=KeyRotateResponse,
    dependencies=[Depends(limiter(10, 60, scope="rotate_key"))],
)
async def rotate_secret_key(
    secret_id: str,
    request: Request,
    current_user: dict = Depends(require_user),
):
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT owner_id FROM secrets WHERE id = %s",
                (secret_id,),
            )
            row = await cur.fetchone()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
    require_owns_secret(str(row[0]) if row[0] else None, current_user)
    try:
        new_version = await rotate_key(pool, secret_id)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=msg) from exc
        # DEK unwrap failure or other internal crypto error — don't leak details to client
        logger.error("Key rotation failed for secret %s: %s", secret_id, exc)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Key rotation failed") from exc
    now = datetime.now(timezone.utc)
    await audit_service.log_critical(
        "key_rotated",
        actor_id=UUID(current_user["id"]),
        actor_ip=request.state.client_ip,
        secret_id=UUID(secret_id),
        metadata={"new_version": new_version},
    )
    return KeyRotateResponse(
        secret_id=UUID(secret_id),
        new_key_version=new_version,
        rotated_at=now,
    )