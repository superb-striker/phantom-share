"""
routers/auth.py – /api/auth/* endpoints.

  POST /api/auth/register   – create account
  POST /api/auth/login      – get access + refresh tokens
  POST /api/auth/refresh    – exchange refresh token
  POST /api/auth/logout     – revoke refresh token + invalidate session
  GET  /api/auth/me         – current user info
"""

from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.database import get_pool
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    verify_password,
    sha256_hash
)
from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.schemas import RefreshRequest, TokenResponse, UserLogin, UserRegister, UserResponse
from app.services import audit_service

settings = get_settings()
router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(limiter(3, 3600, scope="register"))])
async def register(body: UserRegister, request: Request):
    pool = get_pool()
    pw_hash = hash_password(body.password)
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            # Check uniqueness
            await cur.execute(
                "SELECT id FROM users WHERE email = %s OR username = %s",
                (body.email, body.username),
            )
            if await cur.fetchone():
                raise HTTPException(status_code=409, detail="Email or username already taken")
            await cur.execute(
                """
                INSERT INTO users (email, username, password_hash)
                VALUES (%s, %s, %s)
                RETURNING id, email, username, role, is_active, created_at
                """,
                (body.email, body.username, pw_hash),
            )
            row = await cur.fetchone()
    await audit_service.log(
        "user_registered",
        actor_id=str(row[0]),
        actor_ip=request.state.client_ip,
    )
    return UserResponse(
        id=row[0], email=row[1], username=row[2],
        role=row[3], is_active=row[4], created_at=row[5],
    )

@router.post("/login", response_model=TokenResponse, dependencies=[Depends(limiter(5, 60, scope="login"))])
async def login(body: UserLogin, request: Request):
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, password_hash, role, is_active FROM users WHERE email = %s",
                (body.email,),
            )
            row = await cur.fetchone()
        if not row or not verify_password(body.password, row[1]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not row[3]:  # is_active
            raise HTTPException(status_code=403, detail="Account is deactivated")
        user_id, _, role, _ = str(row[0]), row[1], row[2], row[3]
        session_id = str(uuid4())
        access_token = create_access_token(user_id, role, session_id)
        refresh_token, expires_at = create_refresh_token(user_id, session_id)
        refresh_token_hash = sha256_hash(refresh_token)
        # Persist refresh token
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, ip_address, expires_at)
                VALUES (%s, %s, %s, %s, %s::inet, %s)
                """,
                (
                    session_id,
                    user_id,
                    refresh_token_hash,
                    request.headers.get("User-Agent", "")[:256],
                    request.state.client_ip,
                    expires_at,
                ),
            )
    await audit_service.log("user_login", actor_id=user_id, actor_ip=request.state.client_ip)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

@router.post("/refresh", response_model=TokenResponse, dependencies=[Depends(limiter(10, 60, scope="refresh"))])
async def refresh_token_endpoint(body: RefreshRequest, request: Request):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Wrong token type")
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT s.user_id, u.role
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.refresh_token_hash = %s
                  AND s.revoked = FALSE
                  AND s.expires_at > NOW()
                  AND u.is_active = TRUE
                """,
                (sha256_hash(body.refresh_token),),
            )
            row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Refresh token invalid or expired")
        user_id, role = str(row[0]), row[1]
        new_session_id = str(uuid4())
        new_access = create_access_token(user_id, role, new_session_id)
        new_refresh, new_expires = create_refresh_token(user_id, new_session_id)
        new_refresh_hash = sha256_hash(new_refresh)
        # Rotate: revoke old, insert new
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE sessions SET revoked = TRUE WHERE refresh_token_hash = %s",
                (sha256_hash(body.refresh_token),),
            )
            await cur.execute(
                """
                INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, ip_address, expires_at)
                VALUES (%s, %s, %s, %s, %s::inet, %s)
                """,
                (
                    new_session_id,
                    user_id,
                    new_refresh_hash,
                    request.headers.get("User-Agent", "")[:256],
                    request.state.client_ip,
                    new_expires,
                ),
            )
    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshRequest, current_user: dict = Depends(get_current_user)):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Wrong token type")
    sub = payload.get("sub")
    sid = payload.get("sid")
    if not sub or not isinstance(sub, str):
        raise HTTPException(status_code=401, detail="Invalid token subject")
    h = sha256_hash(body.refresh_token)
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            if sid and isinstance(sid, str):
                await cur.execute(
                    """
                    UPDATE sessions SET revoked = TRUE
                    WHERE id = %s AND user_id = %s AND refresh_token_hash = %s AND revoked = FALSE
                    """,
                    (sid, sub, h),
                )
            else:
                await cur.execute(
                    """
                    UPDATE sessions SET revoked = TRUE
                    WHERE refresh_token_hash = %s AND user_id = %s AND revoked = FALSE
                    """,
                    (h, sub),
                )
            if cur.rowcount == 0:
                raise HTTPException(
                    status_code=401,
                    detail="Session not found, already revoked, or refresh token was rotated",
                )
    await audit_service.log("user_logout", actor_id=sub)

@router.get("/me", response_model=UserResponse)
async def me(current_user: dict = Depends(get_current_user)):
    pool = get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, email, username, role, is_active, created_at FROM users WHERE id = %s",
                (current_user["id"],),
            )
            row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found.")
    return UserResponse(
        id=row[0], email=row[1], username=row[2],
        role=row[3], is_active=row[4], created_at=row[5],
    )