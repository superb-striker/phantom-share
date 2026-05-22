"""
rate_limit.py – Sliding-window rate limiting via Redis sorted sets.

Each request occupies one slot in a sorted set keyed by caller identity + scope.
The Lua script is atomic: it prunes stale entries, checks the count, and either
adds the new request or rejects it - all in one round-trip.

The script also returns the oldest request timestamp so the caller can compute
an accurate Retry-After value without a second Redis call.
"""
import logging
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status

from app.core.redis_client import get_redis

logger = logging.getLogger(__name__)

# Lua script :
# Returns a two-element array:
#   [0]  current count after this request (int)
#        – equals max_requests when rejected (request was NOT added)
#   [1]  oldest request timestamp in the window (float as string), or "0"
#        if the window is empty after pruning.
#
# Atomicity guarantee: ZREMRANGEBYSCORE + ZCARD + conditional ZADD run as a
# single Redis transaction, preventing race conditions between concurrent
# requests.

_SLIDING_WINDOW_SCRIPT = """
local key            = KEYS[1]
local now            = tonumber(ARGV[1])
local window_start   = tonumber(ARGV[2])
local window_seconds = tonumber(ARGV[3])
local max_requests   = tonumber(ARGV[4])
local token          = ARGV[5]

-- Prune entries that have fallen outside the window
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

local count = redis.call('ZCARD', key)
if count >= max_requests then
    -- Reject: do NOT add this request to the set
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local oldest_ts = oldest[2] or '0'
    return {count, oldest_ts}
end

-- Accept: record this request
redis.call('ZADD', key, now, token)
redis.call('EXPIRE', key, window_seconds)
return {count + 1, '0'}
"""

# Cache the script SHA after the first SCRIPT LOAD so subsequent calls
# use EVALSHA (sends only 40 bytes) instead of re-sending the full script.
_script_sha: str | None = None


async def _eval_script(redis, key: str, now: float, window_start: float,
                        window_seconds: int, max_requests: int, token: str):
    """Run the rate-limit Lua script, using EVALSHA when the SHA is cached."""
    global _script_sha
    args = [str(now), str(window_start), str(window_seconds), str(max_requests), token]
    if _script_sha is None:
        _script_sha = await redis.script_load(_SLIDING_WINDOW_SCRIPT)
    try:
        return await redis.evalsha(_script_sha, 1, key, *args)
    except Exception:
        # SHA not found (e.g. after a Redis flush/restart) - reload and retry once
        _script_sha = await redis.script_load(_SLIDING_WINDOW_SCRIPT)
        return await redis.evalsha(_script_sha, 1, key, *args)

async def rate_limit(key: str, max_requests: int, window_seconds: int) -> None:
    """
    Enforce the sliding-window rate limit for the given key.

    Raises:
        HTTPException 429: if the caller has exceeded max_requests within
                           the rolling window_seconds window.
    """
    try:
        redis = get_redis()
    except RuntimeError:
        # Fail open: Redis outage disables rate limiting rather than blocking all traffic.
        # Acceptable for availability; add an alert on this log line if abuse is a concern.
        logger.warning("Redis unavailable - skipping rate limit for key %r", key)
        return
    now          = datetime.now(timezone.utc).timestamp()
    window_start = now - window_seconds
    token        = secrets.token_hex(8)   # unique member to avoid sorted-set collisions
    result = await _eval_script(redis, key, now, window_start, window_seconds, max_requests, token)
    count     = int(result[0])
    oldest_ts = float(result[1]) if result[1] != b"0" and result[1] != "0" else None
    if count >= max_requests:
        # Retry-After: time until the oldest request in the window expires,
        # i.e. when the first slot will free up — more accurate than window_seconds.
        if oldest_ts:
            retry_after = max(1, int(oldest_ts + window_seconds - now))
        else:
            retry_after = window_seconds
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Max {max_requests} requests per {window_seconds}s.",
            headers={
                "Retry-After":      str(retry_after),
                "X-RateLimit-Limit": str(max_requests),
                "X-RateLimit-Reset": str(int(now) + retry_after),
            },
        )


# FastAPI dependency factory
def limiter(max_requests: int, window_seconds: int, scope: str = "", force_ip: bool = False):
    """
    Return a FastAPI dependency that enforces a sliding-window rate limit.

    Caller identity resolution (highest priority first):
      1. Authenticated user ID  - unless force_ip=True
      2. client_ip from request.state (set by audit middleware)
      3. Raw request.client.host

    Args:
        max_requests:   Maximum number of requests allowed in the window.
        window_seconds: Rolling window duration in seconds.
        scope:          Logical name for this limit (e.g. "login", "register").
                        Included in the Redis key so different endpoints don't
                        share a bucket.
        force_ip:       When True, always key by IP even for authenticated users.
                        Use this for endpoints where per-IP limiting makes more
                        sense than per-user (e.g. /register, where a single user
                        shouldn't be able to register 10 accounts from one session).
    """
    async def dependency(request: Request) -> None:
        user_id = getattr(request.state, "user_id", None)
        if user_id and not force_ip:
            identifier = f"user:{user_id}"
        else:
            client_ip  = (
                getattr(request.state, "client_ip", None)
                or (request.client.host if request.client else "unknown")
            )
            identifier = f"ip:{client_ip}"
        prefix = f"phantom:ratelimit:{scope}" if scope else "phantom:ratelimit"
        key    = f"{prefix}:{identifier}"
        await rate_limit(key, max_requests, window_seconds)
    return dependency