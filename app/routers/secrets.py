"""
routers/secrets.py – /api/secrets/* endpoints.

  POST   /api/secrets                    – create secret (auth optional)
  POST   /api/secrets/{id}               – retrieve & burn secret
  GET    /api/secrets/{id}               – retrieve share_url (browser friendly)
  GET    /api/secrets/{id}/info          – metadata only
  DELETE /api/secrets/{id}               – delete (owner or admin)
  GET    /api/secrets                    – list own secrets (paginated, filtered)
  POST   /api/secrets/{id}/rotate-key    – rotate encryption key (owner or admin)
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

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
    wrap_dek,
)
from app.schemas import (
    KeyRotateResponse,
    SecretContent,
    SecretCreate,
    SecretCreateResponse,
    SecretInfo,
    SecretListResponse,
    SecretRetrieve,
)
from app.services import audit_service, cleanup_service, email_service
from app.services.key_service import get_dek_for_secret, rotate_key

settings = get_settings()
router = APIRouter(prefix="/api/secrets", tags=["secrets"])


# Create
@router.post("", response_model=SecretCreateResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(limiter(30, 60, scope="secret_create"))])
async def create_secret(
    body: SecretCreate,
    request: Request,
    current_user: Optional[dict] = Depends(get_current_user_optional),
):
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=body.ttl_hours)
    async with get_pool().connection() as conn:
        async with conn.transaction():
            if body.client_encrypted:
                # Client already encrypted - store opaque ciphertext
                if not body.client_nonce:
                    raise HTTPException(400, "client_nonce required when client_encrypted=True")
                encrypted_content = body.content
                nonce = body.client_nonce
                secret_id = await _insert_secret(
                    conn,
                    encrypted_content,
                    nonce,
                    body,
                    owner_id=current_user["id"] if current_user else None,
                )
            else:
                dek = generate_dek()
                wrapped_dek, dek_nonce = wrap_dek(dek)
                encrypted_content, nonce = encrypt_content(body.content, dek)
                secret_id = await _insert_secret(
                    conn,
                    encrypted_content,
                    nonce,
                    body,
                    owner_id=current_user["id"] if current_user else None,
                )
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
            await audit_service.log(
                "secret_created",
                actor_id=current_user["id"] if current_user else None,
                actor_ip=request.state.client_ip,
                secret_id=secret_id,
            )
    share_url = f"{settings.BASE_URL}/api/secrets/{secret_id}?token={signed_token}"
    ttl_secs = body.ttl_hours * 3600
    try:
        await cleanup_service.schedule_expiry(secret_id, ttl_secs)
    except Exception:
        pass
    qr = generate_qr_code(share_url)
    return SecretCreateResponse(
        secret_id=secret_id,
        share_url=share_url,
        signed_token=signed_token,
        expires_at=expires_at,
        qr_code=qr,
    )

async def _insert_secret(conn, content, nonce, body, owner_id) -> str:
    pw_hash = sha256_hash(body.access_password) if body.password_protected and body.access_password else None
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO secrets (
                content, nonce, password_protected, access_password_hash,
                ttl_hours, max_views, notify_on_view,
                notify_email, webhook_url, owner_id
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
            """,
            (
                content,
                nonce,
                body.password_protected,
                pw_hash,
                body.ttl_hours,
                body.max_views,
                body.notify_on_view,
                str(body.notify_email) if body.notify_email else None,
                str(body.webhook_url) if body.webhook_url else None,
                owner_id,
            ),
        )
        row = await cur.fetchone()
    return str(row[0])

# Retrieve & burn
@router.post("/{secret_id}", response_model=SecretContent, dependencies=[Depends(limiter(10, 60, scope="secret_retrieve"))])
async def get_secret(
    secret_id: str,
    body: SecretRetrieve,
    request: Request,
    background_tasks: BackgroundTasks,
    token: Optional[str] = Query(default=None, description="Signed share token"),
    current_user: Optional[dict] = Depends(get_current_user_optional),
):
    if token:
        verified_id = verify_signed_token(token)
        try:
            if UUID(verified_id) != UUID(secret_id):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "Share token does not match this secret",
                )
        except ValueError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid share token") from exc
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT id, content, nonce, password_protected, access_password_hash,
                       viewed, view_count, max_views, expires_at, created_at,
                       notify_on_view, notify_email, webhook_url, owner_id
                FROM secrets
                WHERE id = %s
                """,
                (secret_id,),
            )
            row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Secret not found or has expired")
        (
            _,
            enc_content,
            nonce,
            pw_protected,
            pw_hash,
            viewed,
            view_count,
            max_views,
            expires_at,
            created_at,
            notify_on_view,
            notify_email,
            webhook_url,
            _,
        ) = row
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(410, "Secret has expired")
        if view_count >= max_views:
            raise HTTPException(410, "Secret has reached its maximum view count")
        if pw_protected:
            if not body.access_password:
                raise HTTPException(401, "Password required")
            if sha256_hash(body.access_password) != pw_hash:
                raise HTTPException(401, "Invalid password")
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM secret_keys WHERE secret_id = %s LIMIT 1",
                (secret_id,),
            )
            has_server_key = await cur.fetchone() is not None
        try:
            if has_server_key:
                dek = await get_dek_for_secret(conn, secret_id)
                plaintext = decrypt_content(enc_content, nonce, dek)
                client_encrypted = False
            else:
                plaintext = enc_content
                client_encrypted = True
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(500, "Failed to decrypt secret") from exc
        new_view_count = view_count + 1
        is_now_fully_viewed = new_view_count >= max_views
        actor_ip = request.state.client_ip
        await audit_service.log(
            "secret_viewed",
            actor_id=current_user["id"] if current_user else None,
            actor_ip=actor_ip,
            secret_id=secret_id,
            metadata={"view_count": new_view_count, "max_views": max_views},
        )
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE secrets
                SET view_count = %s,
                    viewed = %s
                WHERE id = %s
                """,
                (new_view_count, is_now_fully_viewed, secret_id),
            )
    if notify_on_view:
        background_tasks.add_task(
            email_service.notify_secret_viewed,
            secret_id,
            notify_email,
            webhook_url,
            actor_ip,
        )
    return SecretContent(
        content=plaintext,
        created_at=created_at,
        expires_at=expires_at,
        views_remaining=max(0, max_views - new_view_count),
        client_encrypted=client_encrypted,
    )

# View secret through share_url
@router.get("/{secret_id}", response_model=SecretContent, dependencies=[Depends(limiter(10, 60, scope="secret_retrieve"))])
async def get_secret_browser(
    secret_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    token: Optional[str] = Query(default=None, description="Signed share token"),
    access_password: Optional[str] = Query(default=None, description="Password if secret is password protected"),
    current_user: Optional[dict] = Depends(get_current_user_optional),
):
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
                       viewed, view_count, max_views, expires_at, created_at,
                       notify_on_view, notify_email, webhook_url, owner_id
                FROM secrets
                WHERE id = %s
                """,
                (secret_id,),
            )
            row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Secret not found or has expired")
        (
            _,
            enc_content,
            nonce,
            pw_protected,
            pw_hash,
            viewed,
            view_count,
            max_views,
            expires_at,
            created_at,
            notify_on_view,
            notify_email,
            webhook_url,
            _,
        ) = row
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(410, "Secret has expired")
        if view_count >= max_views:
            raise HTTPException(410, "Secret has reached its maximum view count")
        if pw_protected:
            if not access_password:
                raise HTTPException(401, "Password required - pass ?access_password=... as a query param")
            if sha256_hash(access_password) != pw_hash:
                raise HTTPException(401, "Invalid password")
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM secret_keys WHERE secret_id = %s LIMIT 1",
                (secret_id,),
            )
            has_server_key = await cur.fetchone() is not None
        try:
            if has_server_key:
                dek = await get_dek_for_secret(conn, secret_id)
                plaintext = decrypt_content(enc_content, nonce, dek)
                client_encrypted = False
            else:
                plaintext = enc_content
                client_encrypted = True
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(500, "Failed to decrypt secret") from exc
        new_view_count = view_count + 1
        is_now_fully_viewed = new_view_count >= max_views
        actor_ip = request.state.client_ip
        await audit_service.log(
            "secret_viewed",
            actor_id=current_user["id"] if current_user else None,
            actor_ip=actor_ip,
            secret_id=secret_id,
            metadata={"view_count": new_view_count, "max_views": max_views},
        )
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE secrets
                SET view_count = %s,
                    viewed = %s
                WHERE id = %s
                """,
                (new_view_count, is_now_fully_viewed, secret_id),
            )
    if notify_on_view:
        background_tasks.add_task(
            email_service.notify_secret_viewed,
            secret_id,
            notify_email,
            webhook_url,
            actor_ip,
        )
    return SecretContent(
        content=plaintext,
        created_at=created_at,
        expires_at=expires_at,
        views_remaining=max(0, max_views - new_view_count),
        client_encrypted=client_encrypted,
    )

# Metadata
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
        raise HTTPException(404, "Secret not found")
    return SecretInfo(
        exists=True,
        created_at=row[0],
        expires_at=row[1],
        password_protected=row[2],
        viewed=row[3],
        view_count=row[4],
        max_views=row[5],
    )

# List (paginated + filtered) - authenticated
@router.get("", response_model=SecretListResponse)
async def list_secrets(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    viewed: Optional[bool] = Query(default=None),
    expired: Optional[bool] = Query(default=None),
    current_user: dict = Depends(require_user),
):
    pool = get_pool()
    offset = (page - 1) * page_size
    conditions = ["owner_id = %s"]
    params: list = [current_user["id"]]
    if viewed is not None:
        conditions.append("viewed = %s")
        params.append(viewed)
    if expired is True:
        conditions.append("expires_at < NOW()")
    elif expired is False:
        conditions.append("expires_at >= NOW()")
    where = " AND ".join(conditions)
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                f"SELECT COUNT(*) FROM secrets WHERE {where}", params
            )
            total = (await cur.fetchone())[0]
            await cur.execute(
                f"""
                SELECT id, created_at, expires_at, viewed, view_count,
                       max_views, password_protected, notify_on_view
                FROM secrets
                WHERE {where}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [page_size, offset],
            )
            rows = await cur.fetchall()
    items = [
        {
            "id": r[0],
            "created_at": r[1],
            "expires_at": r[2],
            "viewed": r[3],
            "view_count": r[4],
            "max_views": r[5],
            "password_protected": r[6],
            "notify_on_view": r[7],
        }
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
                raise HTTPException(404, "Secret not found")
            require_owns_secret(str(row[0]) if row[0] else None, current_user)
            await audit_service.log(
                "secret_deleted",
                actor_id=current_user["id"],
                actor_ip=request.state.client_ip,
                secret_id=secret_id,
            )
            async with conn.cursor() as cur:
                await cur.execute("DELETE FROM secrets WHERE id = %s", (secret_id,))
                if cur.rowcount == 0:
                    raise HTTPException(404, "Secret not found")

# Key rotation
@router.post("/{secret_id}/rotate-key", response_model=KeyRotateResponse, dependencies=[Depends(limiter(5, 60, scope="rotate_key"))])
async def rotate_secret_key(
    secret_id: str,
    request: Request,
    current_user: dict = Depends(require_user),
):
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT owner_id FROM secrets WHERE id = %s", (secret_id,))
            row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Secret not found")
    require_owns_secret(str(row[0]) if row[0] else None, current_user)
    try:
        new_version = await rotate_key(pool, secret_id)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=msg) from exc
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=msg) from exc
    now = datetime.now(timezone.utc)
    await audit_service.log(
        "key_rotated",
        actor_id=current_user["id"],
        actor_ip=request.state.client_ip,
        secret_id=secret_id,
        metadata={"new_version": new_version},
    )
    return KeyRotateResponse(secret_id=secret_id, new_key_version=new_version, rotated_at=now)
