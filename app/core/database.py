from psycopg_pool import AsyncConnectionPool
from app.core.config import get_settings
 
settings = get_settings()
 
pool: AsyncConnectionPool | None = None
 
async def init_pool() -> None:
    global pool
    pool = AsyncConnectionPool(
        settings.DATABASE_URL,
        min_size=settings.DB_MIN_POOL,
        max_size=settings.DB_MAX_POOL,
        open=True,
    )
 
async def close_pool() -> None:
    if pool:
        await pool.close()
 
def get_pool() -> AsyncConnectionPool:
    if pool is None:
        raise RuntimeError("Database pool is not initialized.")
    return pool