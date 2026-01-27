"""
routers/stats.py – /api/stats
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
            await cur.execute(
                "SELECT COUNT(*) FROM secrets WHERE expires_at > NOW()"
            )
            active = (await cur.fetchone())[0]
            await cur.execute("SELECT COUNT(*) FROM secrets")
            total_created = (await cur.fetchone())[0]
            await cur.execute("SELECT COUNT(*) FROM secrets WHERE viewed = TRUE")
            total_viewed = (await cur.fetchone())[0]
    return StatsResponse(
        total_secrets_created=total_created,
        total_secrets_viewed=total_viewed,
        active_secrets=active,
    )