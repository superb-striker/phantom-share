"""
main.py – application entry point.
Startup order:
  1. PostgreSQL connection pool
  2. Redis client
  3. Background expiry worker task
All routers are mounted under their own prefixes.
"""
import asyncio
import uvicorn
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import close_pool, init_pool, get_pool
from app.core.redis_client import close_redis, init_redis
from app.middleware.audit import AuditMiddleware
from app.routers import admin, auth, secrets, stats
from app.services.cleanup_service import expiry_worker

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_pool()
    print("[DB] PostgreSQL pool initialized")
    try:
        await init_redis()
        print("[REDIS] Redis client initialized")
    except Exception as exc:
        print(f"[REDIS] Warning: could not connect to Redis – {exc}")
        print("[REDIS] Expiry scheduling via Redis disabled; DB sweeps still active")
    # Background cleanup task
    cleanup_task = asyncio.create_task(expiry_worker())
    yield  # <- application runs here
    # Shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    await close_pool()
    await close_redis()
    print("[APP] Shutdown complete")

# App
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Secure, time-limited, burn-after-reading secret sharing service. "
        "Supports JWT auth, RBAC, per-secret encryption keys, audit logging, "
        "signed share URLs, email service and webhook notifications."
    ),
    lifespan=lifespan,
)

# Middleware
app.add_middleware(AuditMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router)
app.include_router(secrets.router)
app.include_router(admin.router)
app.include_router(stats.router)

# Health check 
@app.get("/", tags=["health"])
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "ok",
    }

@app.get("/health", tags=["health"])
async def health():
    try:
        pool = get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "database": "ok" if db_ok else "error",
        "status": "ok" if db_ok else "degraded",
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
    )