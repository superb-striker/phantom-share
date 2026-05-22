"""
routers/stats.py – /api/stats

Public endpoint - no auth required.
"""
from fastapi import APIRouter

from app.core.database import get_pool
from app.schemas import StatsResponse

router = APIRouter(prefix="/api", tags=["stats"])

@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            # Active: not yet expired AND still has views remaining
            await cur.execute(
                """
                SELECT COUNT(*)
                FROM secrets
                WHERE expires_at > NOW()
                  AND view_count < max_views
                """
            )
            row = await cur.fetchone()
            active = row[0] if row else 0
            await cur.execute("SELECT COUNT(*) FROM secrets")
            row = await cur.fetchone()
            total_created = row[0] if row else 0
            await cur.execute("SELECT COUNT(*) FROM secrets WHERE viewed = TRUE")
            row = await cur.fetchone()
            total_viewed = row[0] if row else 0
    return StatsResponse(
        total_secrets_created=total_created,
        total_secrets_viewed=total_viewed,
        active_secrets=active,
    )