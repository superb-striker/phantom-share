"""User quota status and administrator quota overrides."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.database import get_pool
from app.core.permissions import require_admin, require_user
from app.schemas_quotas import QuotaResponse, QuotaUpdate
from app.services import audit_service, quota_service

router = APIRouter(prefix="/api", tags=["quotas"])


@router.get("/quota", response_model=QuotaResponse)
async def get_quota(current_user: dict = Depends(require_user)):
    return await quota_service.usage(current_user["id"])


@router.patch("/admin/users/{user_id}/quota", response_model=QuotaResponse)
async def update_quota(
    user_id: UUID,
    body: QuotaUpdate,
    request: Request,
    current_user: dict = Depends(require_admin),
):
    async with get_pool().connection() as conn, conn.cursor() as cur:
        await cur.execute("SELECT 1 FROM users WHERE id = %s", (user_id,))
        if not await cur.fetchone():
            raise HTTPException(404, "User not found")
        await cur.execute(
            """
            INSERT INTO user_quotas(user_id, max_active_secrets, max_file_bytes)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                max_active_secrets = EXCLUDED.max_active_secrets,
                max_file_bytes = EXCLUDED.max_file_bytes,
                updated_at = clock_timestamp()
            """,
            (user_id, body.max_active_secrets, body.max_file_bytes),
        )
    result = await quota_service.usage(str(user_id))
    await audit_service.log_warning(
        "admin_quota_update", actor_id=UUID(current_user["id"]),
        actor_ip=request.state.client_ip,
        metadata={"target_user_id": str(user_id), "quota": result},
    )
    return result
