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
    client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    try:
        await client.config_set("notify-keyspace-events", "Ex")
    except Exception as exc:
        print(
            f"[REDIS] Could not run CONFIG SET notify-keyspace-events (need Ex for expiry events): {exc}"
        )
        print(
            "[REDIS] Fix: allow CONFIG on this Redis, or set notify-keyspace-events Ex in redis.conf. "
            "Until then, only the DB fallback sweep deletes expired secrets."
        )
    _redis = client

async def close_redis() -> None:
    if _redis:
        await _redis.aclose()

def get_redis() -> aioredis.Redis:
    if _redis is None:
        raise RuntimeError("Redis client is not initialized.")
    return _redis