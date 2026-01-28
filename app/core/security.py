import hashlib
import hmac
import time
from uuid import UUID, uuid4
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings
from app.core.database import get_pool


settings = get_settings()
# If token is missing -> don’t immediately throw error, lets us handle auth manually (useful for optional auth routes)
bearer_scheme = HTTPBearer(auto_error=False) 


# Password helpers
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def sha256_hash(password: str) -> str:
    # Lightweight hash used only for secret access passwords/tokens (not user auth).
    return hashlib.sha256(password.encode()).hexdigest()


# JWT helpers

# Consistent time source to avoid timezone bugs when validating tokens
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def create_access_token(user_id: str, role: str, session_id: str) -> str:
    # Used to authenticate for API endpoints. `sid` ties the JWT to a DB session row (revoked on logout).
    payload = {
        "sub": user_id,
        "role": role,
        "sid": session_id,
        "jti": str(uuid4()),
        "exp": _utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": _utcnow(),
        "type": "access", # distinguish access vs refresh
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(user_id: str, session_id: str) -> tuple[str, datetime]:
    # Used to get a new access token without logging in again
    expires_at = _utcnow() + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": user_id,
        "sid": session_id,
        "jti": str(uuid4()),
        "exp": expires_at,
        "iat": _utcnow(),
        "type": "refresh",
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, expires_at


def decode_token(token: str) -> dict:
    # Verifies: Signature (was it signed by you?), Expiry (exp) 
    # Returns payload if valid
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# Signed share-link tokens
def create_signed_token(secret_id: UUID, expires_in_hours: int) -> str:
    """
    Returns a URL-safe signed token: <secret_id>.<ts>.<sig>
    No DB round-trip needed to validate.
    """
    ts = int(time.time()) + expires_in_hours * 3600
    payload = f"{secret_id}.{ts}"
    sig = hmac.new(
        settings.SIGNED_URL_SECRET.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{sig}"

def verify_signed_token(token: str) -> str:
    # Validates the token and returns secret_id, or raises 403
    try:
        secret_id, ts_str, sig = token.rsplit(".", 2)
    except ValueError:
        raise HTTPException(status_code=403, detail="Invalid share token")
    ts = int(ts_str)
    if time.time() > ts:
        raise HTTPException(status_code=403, detail="Share token has expired")
    payload = f"{secret_id}.{ts}"
    expected = hmac.new(
        settings.SIGNED_URL_SECRET.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=403, detail="Invalid share token signature")
    return secret_id


# FastAPI dependency: current user
# For protected routes (must login)
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Wrong token type")
    sub = payload.get("sub")
    sid = payload.get("sid")
    if not sub or not isinstance(sub, str):
        raise HTTPException(status_code=401, detail="Invalid user ID")
    if not sid or not isinstance(sid, str):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT u.id, u.email, u.username, u.role, u.is_active
                FROM users u
                INNER JOIN sessions s ON s.user_id = u.id
                WHERE u.id = %s
                  AND s.id = %s
                  AND s.revoked = FALSE
                  AND s.expires_at > NOW()
                """,
                (sub, sid),
            )
            row = await cur.fetchone()
    if not row or not row[4]:  # is_active
        raise HTTPException(
            status_code=401,
            detail="Session revoked, expired, or user inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"id": str(row[0]), "email": row[1], "username": row[2], "role": row[3]}

# For public routes (optional login)
async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> Optional[dict]:
    # Returns user dict or None for anonymous requests
    if not credentials:
        return None
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None