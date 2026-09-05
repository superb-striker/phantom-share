import time
import uuid

import pytest
from fastapi import HTTPException

import app.core.security as security

class _FakeCursor:
    def __init__(self, fetchone_result):
        self._fetchone_result = fetchone_result
    async def __aenter__(self):
        return self
    async def __aexit__(self, *exc):
        return False
    async def execute(self, *args, **kwargs):
        return None
    async def fetchone(self):
        return self._fetchone_result

class _FakeConnection:
    def __init__(self, fetchone_result):
        self._fetchone_result = fetchone_result
    async def __aenter__(self):
        return self
    async def __aexit__(self, *exc):
        return False
    def cursor(self):
        return _FakeCursor(self._fetchone_result)

class _FakePool:
    def __init__(self, fetchone_result):
        self._fetchone_result = fetchone_result
    def connection(self):
        return _FakeConnection(self._fetchone_result)

class _FakeCredentials:
    def __init__(self, token):
        self.credentials = token


class TestPasswordHashing:
    def test_hash_and_verify_round_trip(self):
        hashed = security.hash_password("correct horse battery staple")
        assert security.verify_password("correct horse battery staple", hashed)

    def test_verify_rejects_wrong_password(self):
        hashed = security.hash_password("correct horse battery staple")
        assert not security.verify_password("wrong password", hashed)

    def test_hash_is_salted_differently_each_time(self):
        h1 = security.hash_password("same password")
        h2 = security.hash_password("same password")
        assert h1 != h2

    def test_sha256_hash_is_deterministic(self):
        assert security.sha256_hash("value") == security.sha256_hash("value")

    def test_sha256_hash_differs_for_different_input(self):
        assert security.sha256_hash("value1") != security.sha256_hash("value2")


class TestAccessToken:
    def test_create_and_decode_round_trip(self):
        token = security.create_access_token("user-123", "user", "session-abc")
        payload = security.decode_token(token)
        assert payload["sub"] == "user-123"
        assert payload["role"] == "user"
        assert payload["sid"] == "session-abc"
        assert payload["type"] == "access"

    def test_decode_expired_token_raises_401(self, monkeypatch):
        monkeypatch.setattr(security.settings, "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", -1)
        token = security.create_access_token("user-123", "user", "session-abc")
        with pytest.raises(HTTPException) as exc_info:
            security.decode_token(token)
        assert exc_info.value.status_code == 401

    def test_decode_tampered_token_raises_401(self):
        token = security.create_access_token("user-123", "user", "session-abc")
        tampered = token[:-4] + ("A" * 4)
        with pytest.raises(HTTPException) as exc_info:
            security.decode_token(tampered)
        assert exc_info.value.status_code == 401

    def test_decode_token_signed_with_wrong_key_rejected(self, monkeypatch):
        token = security.create_access_token("user-123", "user", "session-abc")
        monkeypatch.setattr(security.settings, "JWT_SECRET_KEY", "a-completely-different-key")
        with pytest.raises(HTTPException):
            security.decode_token(token)

    def test_each_token_has_unique_jti(self):
        t1 = security.create_access_token("user-123", "user", "session-abc")
        t2 = security.create_access_token("user-123", "user", "session-abc")
        assert security.decode_token(t1)["jti"] != security.decode_token(t2)["jti"]


class TestRefreshToken:
    def test_create_refresh_token_has_correct_type_and_expiry(self):
        token, expires_at = security.create_refresh_token("user-123", "session-abc")
        payload = security.decode_token(token)
        assert payload["type"] == "refresh"
        assert payload["sub"] == "user-123"
        assert int(expires_at.timestamp()) == payload["exp"]

    def test_refresh_token_expiry_matches_configured_days(self):
        _, expires_at = security.create_refresh_token("user-123", "session-abc")
        now = security._utcnow()
        delta_days = (expires_at - now).days
        assert abs(delta_days - security.settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS) <= 1


class TestSignedShareToken:
    SECRET_ID = "00000000-0000-0000-0000-000000000001"

    def test_create_and_verify_round_trip(self):
        token = security.create_signed_token(self.SECRET_ID, expires_in_hours=1)
        assert security.verify_signed_token(token) == self.SECRET_ID

    def test_expired_token_rejected(self):
        token = security.create_signed_token(self.SECRET_ID, expires_in_hours=0)
        time.sleep(1.1)
        with pytest.raises(HTTPException) as exc_info:
            security.verify_signed_token(token)
        assert exc_info.value.status_code == 403
        assert "expired" in exc_info.value.detail.lower()

    def test_tampered_signature_rejected(self):
        token = security.create_signed_token(self.SECRET_ID, expires_in_hours=1)
        secret_part, ts_part, sig_part = token.rsplit(".", 2)
        tampered = f"{secret_part}.{ts_part}.{'f' * len(sig_part)}"
        with pytest.raises(HTTPException) as exc_info:
            security.verify_signed_token(tampered)
        assert exc_info.value.status_code == 403

    def test_tampered_secret_id_rejected(self):
        token = security.create_signed_token(self.SECRET_ID, expires_in_hours=1)
        _, ts_part, sig_part = token.rsplit(".", 2)
        tampered = f"11111111-1111-1111-1111-111111111111.{ts_part}.{sig_part}"
        with pytest.raises(HTTPException) as exc_info:
            security.verify_signed_token(tampered)
        assert exc_info.value.status_code == 403

    def test_malformed_token_missing_parts_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            security.verify_signed_token("not-a-valid-token")
        assert exc_info.value.status_code == 403

    def test_non_integer_timestamp_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            security.verify_signed_token("secret-id.not-a-timestamp.somesig")
        assert exc_info.value.status_code == 403


class TestGetCurrentUser:
    """
    DB layer is faked here rather than hit for real, since what's under
    test is get_current_user's branching logic (token type, missing
    claims, session validity) - not SQL correctness. Add a real-Postgres
    integration test separately if you also want to verify the JOIN
    itself against your actual schema.
    """

    @pytest.mark.asyncio
    async def test_no_credentials_raises_401(self):
        with pytest.raises(HTTPException) as exc_info:
            await security.get_current_user(credentials=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_token_type_rejected(self):
        token, _ = security.create_refresh_token("user-123", "session-abc")
        with pytest.raises(HTTPException) as exc_info:
            await security.get_current_user(credentials=_FakeCredentials(token))
        assert exc_info.value.status_code == 401
        assert "wrong token type" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_valid_token_and_active_session_returns_user(self, monkeypatch):
        token = security.create_access_token("user-123", "user", "session-abc")
        fake_row = ("user-123", "a@b.com", "alice", "user", True)
        monkeypatch.setattr(security, "get_pool", lambda: _FakePool(fake_row))

        user = await security.get_current_user(credentials=_FakeCredentials(token))
        assert user == {
            "id": "user-123", "email": "a@b.com", "username": "alice",
            "role": "user", "is_active": True,
        }

    @pytest.mark.asyncio
    async def test_revoked_or_missing_session_rejected(self, monkeypatch):
        token = security.create_access_token("user-123", "user", "session-abc")
        monkeypatch.setattr(security, "get_pool", lambda: _FakePool(None))
        with pytest.raises(HTTPException) as exc_info:
            await security.get_current_user(credentials=_FakeCredentials(token))
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_inactive_user_rejected_even_with_valid_session_row(self, monkeypatch):
        token = security.create_access_token("user-123", "user", "session-abc")
        fake_row = ("user-123", "a@b.com", "alice", "user", False)  # is_active=False
        monkeypatch.setattr(security, "get_pool", lambda: _FakePool(fake_row))
        with pytest.raises(HTTPException) as exc_info:
            await security.get_current_user(credentials=_FakeCredentials(token))
        assert exc_info.value.status_code == 401


class TestGetCurrentUserOptional:
    @pytest.mark.asyncio
    async def test_no_credentials_returns_none(self):
        assert await security.get_current_user_optional(credentials=None) is None

    @pytest.mark.asyncio
    async def test_invalid_token_returns_none_not_raise(self):
        result = await security.get_current_user_optional(credentials=_FakeCredentials("garbage-token"))
        assert result is None

    @pytest.mark.asyncio
    async def test_server_error_still_propagates(self, monkeypatch):
        async def fake_get_current_user(credentials):
            raise HTTPException(status_code=500, detail="db exploded")

        monkeypatch.setattr(security, "get_current_user", fake_get_current_user)
        with pytest.raises(HTTPException) as exc_info:
            await security.get_current_user_optional(credentials=_FakeCredentials("whatever"))
        assert exc_info.value.status_code == 500
