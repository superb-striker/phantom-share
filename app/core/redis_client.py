import redis.asyncio as aioredis
from app.core.config import get_settings

settings = get_settings()

'''
- Enable keyspace notifications in Redis so it emits an event when a key expires
- Subscribe to those events in the worker instead of polling on a timer
- When a notification fires for phantom:expiry:<secret_id>, delete that specific row from PostgreSQL.
'''

_redis: aioredis.Redis | None = None

async def init_redis() -> None:
    global _redis
    _redis = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    # Enable expired-key events on database 0
    await _redis.config_set("notify-keyspace-events", "Ex")

async def close_redis() -> None:
    if _redis:
        await _redis.aclose()

def get_redis() -> aioredis.Redis:
    if _redis is None:
        raise RuntimeError("Redis client is not initialized.")
    return _redis