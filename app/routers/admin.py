"""
routers/admin.py – /api/admin/* endpoints (admin role required).

  DELETE /api/admin/cleanup                 – hard-purge expired secrets
  GET    /api/admin/audit-logs              – paginated audit log viewer
  GET    /api/admin/users                   – list all users
  PATCH  /api/admin/users/{id}/role         – change a user's role
  PATCH  /api/admin/users/{id}/deactivate   - make a user inactive 
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.database import get_pool
from app.core.permissions import require_admin
from app.schemas import AuditLogItem, AuditLogResponse, UserResponse
from app.services import cleanup_service

router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.delete("/cleanup")
async def cleanup_expired(current_user: dict = Depends(require_admin)):
    deleted = await cleanup_service._fallback_sweep()
    return {"deleted_count": deleted}

@router.get("/audit-logs", response_model=AuditLogResponse)
async def audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    action: Optional[str] = Query(default=None),
    actor_id: Optional[UUID] = Query(default=None),
    secret_id: Optional[str] = Query(default=None),
    current_user: dict = Depends(require_admin),
):
    pool = get_pool()
    conditions = ["1=1"]
    params: list = []
    if action:
        conditions.append("action = %s::audit_action")
        params.append(action)
    if actor_id:
        conditions.append("actor_id = %s")
        params.append(str(actor_id))
    if secret_id:
        conditions.append("secret_id = %s")
        params.append(secret_id)
    where = " AND ".join(conditions)
    offset = (page - 1) * page_size
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(f"SELECT COUNT(*) FROM audit_logs WHERE {where}", params)
            total = (await cur.fetchone())[0]
            await cur.execute(
                f"""
                SELECT id, action, actor_id, actor_ip, secret_id, metadata, created_at
                FROM audit_logs
                WHERE {where}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [page_size, offset],
            )
            rows = await cur.fetchall()
    items = [
        AuditLogItem(
            id=r[0], action=r[1], actor_id=r[2],
            actor_ip=str(r[3]) if r[3] else None,
            secret_id=r[4], metadata=r[5] or {}, created_at=r[6],
        )
        for r in rows
    ]
    return AuditLogResponse(items=items, total=total, page=page, page_size=page_size)

@router.get("/users")
async def list_users(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    current_user: dict = Depends(require_admin),
):
    pool = get_pool()
    offset = (page - 1) * page_size
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT COUNT(*) FROM users")
            total = (await cur.fetchone())[0]
            await cur.execute(
                """
                SELECT id, email, username, role, is_active, created_at
                FROM users
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                (page_size, offset),
            )
            rows = await cur.fetchall()
    items = [
        UserResponse(
            id=r[0], email=r[1], username=r[2],
            role=r[3], is_active=r[4], created_at=r[5],
        )
        for r in rows
    ]
    return {"items": items, "total": total, "page": page, "page_size": page_size}

@router.patch("/users/{user_id}/role")
async def change_role(
    user_id: UUID,
    role: str = Query(..., pattern="^(admin|user|readonly)$"),
    current_user: dict = Depends(require_admin),
):
    if str(user_id) == current_user["id"]:
        raise HTTPException(400, "Cannot change your own role")
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE users SET role = %s::user_role WHERE id = %s RETURNING id",
                (role, str(user_id)),
            )
            if not await cur.fetchone():
                raise HTTPException(404, "User not found")
    return {"user_id": str(user_id), "new_role": role}

@router.patch("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: UUID,
    current_user: dict = Depends(require_admin),
):
    if str(user_id) == current_user["id"]:
        raise HTTPException(400, "Cannot deactivate yourself")
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE users SET is_active = FALSE WHERE id = %s RETURNING id",
                (str(user_id),),
            )
            if not await cur.fetchone():
                raise HTTPException(404, "User not found")
    return {"user_id": str(user_id), "status": "deactivated"}