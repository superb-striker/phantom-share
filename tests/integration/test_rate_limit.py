import asyncio

import pytest
from fastapi import HTTPException

import app.core.rate_limit as rate_limit


@pytest.fixture(autouse=True)
def _patch_redis(monkeypatch, redis_client):
    monkeypatch.setattr(rate_limit, "get_redis", lambda: redis_client)
    # Reset the cached Lua SHA between tests since each test may run
    # against a freshly-flushed Redis (script cache lives server-side).
    monkeypatch.setattr(rate_limit, "_script_sha", None)


class _FakeRequest:
    """Minimal stand-in for fastapi.Request exposing only what limiter() reads."""
    def __init__(self, user_id, client_ip):
        self.state = type("State", (), {"user_id": user_id, "client_ip": client_ip})()
        self.client = type("Client", (), {"host": client_ip})()


class TestSlidingWindowRateLimit:
    @pytest.mark.asyncio
    async def test_allows_requests_up_to_the_limit(self):
        for _ in range(5):
            await rate_limit.rate_limit("test:key:a", max_requests=5, window_seconds=60)

    @pytest.mark.asyncio
    async def test_rejects_the_request_over_the_limit(self):
        for _ in range(5):
            await rate_limit.rate_limit("test:key:b", max_requests=5, window_seconds=60)
        with pytest.raises(HTTPException) as exc_info:
            await rate_limit.rate_limit("test:key:b", max_requests=5, window_seconds=60)
        assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_429_includes_retry_after_headers(self):
        for _ in range(2):
            await rate_limit.rate_limit("test:key:c", max_requests=2, window_seconds=30)
        with pytest.raises(HTTPException) as exc_info:
            await rate_limit.rate_limit("test:key:c", max_requests=2, window_seconds=30)
        headers = exc_info.value.headers
        assert "Retry-After" in headers
        assert headers["X-RateLimit-Limit"] == "2"

    @pytest.mark.asyncio
    async def test_different_keys_have_independent_windows(self):
        for _ in range(3):
            await rate_limit.rate_limit("test:key:d1", max_requests=3, window_seconds=60)
        await rate_limit.rate_limit("test:key:d2", max_requests=3, window_seconds=60)

    @pytest.mark.asyncio
    async def test_window_slides_and_allows_requests_again(self):
        for _ in range(2):
            await rate_limit.rate_limit("test:key:e", max_requests=2, window_seconds=1)
        with pytest.raises(HTTPException):
            await rate_limit.rate_limit("test:key:e", max_requests=2, window_seconds=1)
        await asyncio.sleep(1.2)
        await rate_limit.rate_limit("test:key:e", max_requests=2, window_seconds=1)

    @pytest.mark.asyncio
    async def test_concurrent_requests_at_the_boundary_are_serialized_correctly(self):
        """
        Fires 2x max_requests concurrently at an empty key and asserts
        exactly max_requests succeed - this is the actual proof that the
        Lua script's atomicity (ZREMRANGEBYSCORE + ZCARD + ZADD in one
        round-trip) holds under concurrency, not just sequential calls.
        """
        max_requests = 10
        results = await asyncio.gather(
            *[
                rate_limit.rate_limit("test:key:concurrent", max_requests, window_seconds=60)
                for _ in range(max_requests * 2)
            ],
            return_exceptions=True,
        )
        successes = [r for r in results if r is None]
        rejections = [r for r in results if isinstance(r, HTTPException)]
        assert len(successes) == max_requests
        assert len(rejections) == max_requests

    @pytest.mark.asyncio
    async def test_evalsha_recovers_after_script_flush(self):
        """
        Simulates Redis losing the cached script (e.g. restart / FLUSHALL)
        while the module-level _script_sha global still holds the old,
        now-invalid SHA. The try/except fallback in _eval_script should
        reload and retry rather than raising NOSCRIPT to the caller.
        """
        await rate_limit.rate_limit("test:key:f", max_requests=5, window_seconds=60)
        redis = rate_limit.get_redis()
        await redis.script_flush()
        await rate_limit.rate_limit("test:key:f", max_requests=5, window_seconds=60)


class TestFailOpenBehavior:
    @pytest.mark.asyncio
    async def test_fails_open_when_redis_unavailable(self, monkeypatch):
        def _raise():
            raise RuntimeError("redis not connected")
        monkeypatch.setattr(rate_limit, "get_redis", _raise)
        # Must NOT raise - documented fail-open design disables limiting
        # rather than blocking all traffic during a Redis outage.
        await rate_limit.rate_limit("test:key:g", max_requests=1, window_seconds=60)
        await rate_limit.rate_limit("test:key:g", max_requests=1, window_seconds=60)


class TestLimiterDependencyKeying:
    @pytest.mark.asyncio
    async def test_authenticated_user_keyed_by_user_id(self, monkeypatch):
        captured = {}
        async def fake_rate_limit(key, max_requests, window_seconds):
            captured["key"] = key
        monkeypatch.setattr(rate_limit, "rate_limit", fake_rate_limit)

        request = _FakeRequest(user_id="user-42", client_ip="1.2.3.4")
        dependency = rate_limit.limiter(max_requests=5, window_seconds=60, scope="login")
        await dependency(request)
        assert captured["key"] == "phantom:ratelimit:login:user:user-42"

    @pytest.mark.asyncio
    async def test_force_ip_keys_by_ip_even_when_authenticated(self, monkeypatch):
        captured = {}
        async def fake_rate_limit(key, max_requests, window_seconds):
            captured["key"] = key
        monkeypatch.setattr(rate_limit, "rate_limit", fake_rate_limit)

        request = _FakeRequest(user_id="user-42", client_ip="1.2.3.4")
        dependency = rate_limit.limiter(max_requests=5, window_seconds=60, scope="register", force_ip=True)
        await dependency(request)
        assert captured["key"] == "phantom:ratelimit:register:ip:1.2.3.4"

    @pytest.mark.asyncio
    async def test_anonymous_request_keyed_by_ip(self, monkeypatch):
        captured = {}
        async def fake_rate_limit(key, max_requests, window_seconds):
            captured["key"] = key
        monkeypatch.setattr(rate_limit, "rate_limit", fake_rate_limit)

        request = _FakeRequest(user_id=None, client_ip="5.6.7.8")
        dependency = rate_limit.limiter(max_requests=5, window_seconds=60)
        await dependency(request)
        assert captured["key"] == "phantom:ratelimit:ip:5.6.7.8"
