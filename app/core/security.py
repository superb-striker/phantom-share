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
    '''Hash a plaintext password using bcrypt.'''
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

def verify_password(plain: str, hashed: str) -> bool:
    '''Verify a plaintext password against a bcrypt hash.'''
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def sha256_hash(password: str) -> str:
    '''Generate a SHA-256 hash for lightweight token/secret protection. (not used for user auth)'''
    return hashlib.sha256(password.encode()).hexdigest()


# JWT helpers

# Consistent time source to avoid timezone bugs when validating tokens
def _utcnow() -> datetime:
    '''Return the current UTC datetime.'''
    return datetime.now(timezone.utc)

def create_access_token(user_id: str, role: str, session_id: str) -> str:
    '''Create and return a signed JWT access token for authenticated API access. '''
    payload = {
        "sub": user_id,
        "role": role,
        "sid": session_id,  # ties the JWT to a DB session row (revoked on logout).
        "jti": str(uuid4()),
        "exp": _utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": _utcnow(),
        "type": "access",   # distinguish access vs refresh
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(user_id: str, session_id: str) -> tuple[str, datetime]:
    '''Create a signed JWT refresh token which is used to get a new access token without logging in again.'''
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
    '''Decode and validate a JWT token, raising 401 if invalid or expired. \n
    Verifies: Signature (was it signed by you?), Expiry (exp) and returns payload if valid'''
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# Signed share-link tokens
def create_signed_token(secret_id: UUID, expires_in_hours: int) -> str:
    ''' Generate a signed, time-limited share token for a secret. \n
    Returns a URL-safe signed token: <secret_id>.<ts>.<sig> 
    '''
    ts = int(time.time()) + expires_in_hours * 3600
    payload = f"{secret_id}.{ts}"
    sig = hmac.new(
        settings.SIGNED_URL_SECRET.encode(),
        payload.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{sig}"

def verify_signed_token(token: str) -> str:
    '''Validate a signed share token and return its associated secret ID  or raises 403 if invalid'''
    try:
        secret_id, ts_str, sig = token.rsplit(".", 2)
    except ValueError:
        raise HTTPException(status_code=403, detail="Invalid share token")
    try:
        ts = int(ts_str)
    except ValueError:
        raise HTTPException(status_code=403, detail="Invalid share token")
    if time.time() > ts:
        raise HTTPException(status_code=403, detail="Share token has expired")
    payload = f"{secret_id}.{ts}"
    expected = hmac.new(
        settings.SIGNED_URL_SECRET.encode(),
        payload.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=403, detail="Invalid share token signature")
    return secret_id


# FastAPI dependency: current user
# For protected routes (must login)
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> dict:
    '''Authenticate the current user from a Bearer token and return the user details if validated.'''
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
    return {"id": str(row[0]), "email": row[1], "username": row[2], "role": row[3],  "is_active": row[4]}

# For public routes (optional login)
async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> Optional[dict]:
    '''Return the authenticated user if valid, and None for anonymous requests'''
    if not credentials:
        return None
    try:
        return await get_current_user(credentials)
    except HTTPException as exc:
        # Only swallow auth failures, not server errors
        if exc.status_code in (401, 403):
            return None
        raise