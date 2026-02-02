# app/core/rate_limit.py
from datetime import datetime, timezone
from fastapi import HTTPException, Request, status
from app.core.redis_client import get_redis

async def rate_limit(key: str, max_requests: int, window_seconds: int) -> None:
    redis = get_redis()
    now = datetime.now(timezone.utc).timestamp()
    window_start = now - window_seconds
    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, window_start)       # drop expired entries
    pipe.zadd(key, {str(now): now})                   # add current request
    pipe.zcard(key)                                   # count in window
    pipe.expire(key, window_seconds)                  # auto-cleanup key
    results = await pipe.execute()
    request_count = results[2]
    if request_count > max_requests:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Max {max_requests} requests per {window_seconds}s.",
            headers={"Retry-After": str(window_seconds)},
        )

def limiter(max_requests: int, window_seconds: int, scope: str = ""):
    # Returns a FastAPI dependency with the given limits
    async def dependency(request: Request):
        # Use user ID if authenticated, fall back to IP
        user_id = getattr(request.state, "user_id", None)
        identifier = f"user:{user_id}" if user_id else f"ip:{request.state.client_ip}"
        key = f"phantom:ratelimit:{scope}:{identifier}"
        await rate_limit(key, max_requests, window_seconds)
    return dependency