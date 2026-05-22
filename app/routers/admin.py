"""
routers/admin.py – /api/admin/* endpoints (admin role required).

  DELETE /api/admin/cleanup                 – hard-purge expired secrets
  GET    /api/admin/audit-logs              – paginated audit log viewer
  GET    /api/admin/users                   – list all users
  PATCH  /api/admin/users/{id}/role         – change a user's role
  PATCH  /api/admin/users/{id}/switch       - toggle active /inactive status
"""
from typing import Optional
from uuid import UUID
from psycopg import sql
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.core.database import get_pool
from app.core.permissions import require_admin
from app.schemas import (
    AdminUserListResponse,
    AdminUserResponse,
    AuditLogItem,
    AuditLogResponse,
    AuditSeverity,
    CleanupResponse,
    RoleUpdateRequest,
    UserStatusResponse,
)
from app.services import audit_service, cleanup_service

router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.delete("/cleanup", response_model=CleanupResponse)
async def cleanup_expired(
    request: Request,
    current_user: dict = Depends(require_admin),
):
    """
    Manually trigger the fallback sweep.
    Hard-deletes expired secrets, stale sessions, and deactivated users
    that have passed their delete_after grace period.
    """
    result = await cleanup_service.fallback_sweep()
    await audit_service.log_warning(
        "admin_cleanup",
        actor_id=current_user["id"],
        actor_ip=request.state.client_ip
    )
    return result

@router.get("/audit-logs", response_model=AuditLogResponse)
async def audit_logs(
    page:      int           = Query(default=1,  ge=1),
    page_size: int           = Query(default=50, ge=1, le=200),
    action:    Optional[str] = Query(default=None, description="Filter by audit_action value"),
    severity:  Optional[str] = Query(default=None, description="Filter by severity: info | warning | critical"),
    actor_id:  Optional[UUID] = Query(default=None),
    secret_id: Optional[UUID] = Query(default=None),
    current_user: dict = Depends(require_admin),
):
    pool = get_pool()
    conditions: list[sql.Composable] = [sql.SQL("TRUE")]
    params: list = []
    if action:
        conditions.append(sql.SQL("action = %s::audit_action"))
        params.append(action)
    if severity:
        conditions.append(sql.SQL("severity = %s::audit_severity"))
        params.append(severity)
    if actor_id:
        conditions.append(sql.SQL("actor_id = %s::uuid"))
        params.append(str(actor_id))
    if secret_id:
        conditions.append(sql.SQL("secret_id = %s::uuid"))
        params.append(str(secret_id))
    where  = sql.SQL(" AND ").join(conditions)
    offset = (page - 1) * page_size
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            # Total count for pagination metadata
            await cur.execute(
                sql.SQL("SELECT COUNT(*) FROM audit_logs WHERE {}").format(where),
                params,
            )
            row   = await cur.fetchone()
            total = row[0] if row else 0
            await cur.execute(
                sql.SQL("""
                    SELECT id, action, severity, actor_id, actor_ip,
                           secret_id, metadata, created_at
                    FROM audit_logs
                    WHERE {}
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """).format(where),
                params + [page_size, offset],
            )
            rows = await cur.fetchall()
    items = [
        AuditLogItem(
            id=r[0],
            action=r[1],
            severity=r[2],
            actor_id=r[3],
            actor_ip=str(r[4]) if r[4] else None,
            secret_id=r[5],
            metadata=r[6] or {},
            created_at=r[7],
        )
        for r in rows
    ]
    return AuditLogResponse(items=items, total=total, page=page, page_size=page_size)

@router.get("/users", response_model=AdminUserListResponse)
async def list_users(
    page:      int = Query(default=1,  ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    current_user: dict = Depends(require_admin),
):
    pool   = get_pool()
    offset = (page - 1) * page_size
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT COUNT(*) FROM users")
            row   = await cur.fetchone()
            total = row[0] if row else 0
            # Return all admin-visible columns including updated_at / delete_after
            await cur.execute(
                """
                SELECT id, email, username, role, is_active, 
                       created_at, updated_at, delete_after
                FROM users
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                (page_size, offset),
            )
            rows = await cur.fetchall()
    items = [
        AdminUserResponse(
            id=r[0], email=r[1], username=r[2],
            role=r[3], is_active=r[4], created_at=r[5], updated_at=r[6], delete_after=r[7],
        )
        for r in rows
    ]
    return AdminUserListResponse(items=items, total=total, page=page, page_size=page_size)

@router.patch("/users/{user_id}/role", response_model=AdminUserResponse)
async def change_role(
    user_id: UUID,
    body:    RoleUpdateRequest,
    request: Request,
    current_user: dict = Depends(require_admin),
):
    """
    Change a user's role.
    Admins cannot demote themselves to avoid accidental lockout.
    Role arrives as a typed RoleUpdateRequest body (not a raw query param)
    so it's validated by Pydantic before reaching the DB.
    """
    if str(user_id) == str(current_user["id"]):
        raise HTTPException(400, "Cannot change your own role")
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE users SET role = %s::user_role WHERE id = %s
                RETURNING id, email, username, role, is_active,
                          created_at, updated_at, delete_after
                """,
                (body.role, str(user_id)),
            )
            row = await cur.fetchone()
 
    if not row:
        raise HTTPException(404, "User not found")
    await audit_service.log_critical(
        "admin_role_change",
        actor_id=current_user["id"],
        actor_ip=request.state.client_ip,
        metadata={"target_user_id": str(user_id), "new_role": body.role},
    )
    return AdminUserResponse(
        id=row[0], email=row[1], username=row[2],
        role=row[3], is_active=row[4], 
        created_at=row[5], updated_at=row[6], delete_after=row[7],
    )

@router.patch("/users/{user_id}/switch", response_model=UserStatusResponse)
async def switch_user_activation(
    user_id: UUID,
    request: Request,
    current_user: dict = Depends(require_admin),
):
    """
    Toggle a user's is_active flag.
    Deactivating schedules deletion via the DB trigger (delete_after = NOW() + 2 days).
    Reactivating clears delete_after.
    """
    if str(user_id) == str(current_user["id"]):
        raise HTTPException(400, "Cannot change your own activation status")
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE users SET is_active = NOT is_active WHERE id = %s
                RETURNING id, is_active, delete_after
                """,
                (str(user_id),),
            )
            row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "User not found")
    await audit_service.log_warning(
        "admin_user_toggle",
        actor_id=current_user["id"],
        actor_ip=request.state.client_ip,
        metadata={"target_user_id": str(user_id), "is_active": row[1]},
    )
    return UserStatusResponse(user_id=row[0], is_active=row[1], delete_after=row[2])