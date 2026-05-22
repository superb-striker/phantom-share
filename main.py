"""
main.py – Application entry point.
"""
import asyncio
import uvicorn
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import close_pool, init_pool, get_pool
from app.core.redis_client import close_redis, init_redis
from app.middleware.audit import AuditMiddleware
from app.routers import admin, auth, secrets, stats
from app.services.cleanup_service import expiry_worker
from app.services.notification_worker import notification_worker, stop_worker

settings = get_settings()
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_pool()
    logger.info("PostgreSQL pool initialized")
    try:
        await init_redis()
        logger.info("Redis client initialized")
    except Exception as exc:
        logger.warning(
            "Could not connect to Redis: %s - "
            "expiry scheduling via Redis disabled; DB sweeps still active", exc,
        )
    
    rabbitmq_ready = asyncio.Event()
    cleanup_task      = asyncio.create_task(expiry_worker())
    notification_task = asyncio.create_task(notification_worker(ready_event=rabbitmq_ready))
    
    def handle_worker_crash(task: asyncio.Task):
        try:
            task.result()
        except asyncio.CancelledError:
            pass  
        except Exception as e:
            logger.error("A background worker crashed unexpectedly!", exc_info=True)
            
    cleanup_task.add_done_callback(handle_worker_crash)
    notification_task.add_done_callback(handle_worker_crash)
    
    # Active startup health-check loop
    loop_timeout = 5.0
    start_time = asyncio.get_event_loop().time()
    while not rabbitmq_ready.is_set():
        if notification_task.done():
            # If it crashed instantly, break out and bubble up the real error trace
            notification_task.result() 
            break
        if (asyncio.get_event_loop().time() - start_time) > loop_timeout:
            logger.warning("RabbitMQ initialization timed out...")
            break
        await asyncio.sleep(0.1)
        
    if rabbitmq_ready.is_set():
        logger.info("RabbitMQ connection established and queues initialized")

    yield  # application runs here
    
    # Shutdown
    await stop_worker()
    try:
        await asyncio.wait_for(notification_task, timeout=10.0)
    except asyncio.TimeoutError:
        logger.warning("Notification worker did not stop in time; cancelling")
        notification_task.cancel()
        try:
            await notification_task
        except asyncio.CancelledError:
            pass
    except asyncio.CancelledError:
        pass
        
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
        
    await close_pool()
    await close_redis()
    logger.info("Shutdown complete")
    

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Secure, time-limited, burn-after-reading secret sharing service. "
        "Supports JWT auth, RBAC, per-secret encryption keys, "
        "signed share URLs, email and webhook notifications."
    ),
    lifespan=lifespan,
)

app.add_middleware(AuditMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(secrets.router)
app.include_router(admin.router)
app.include_router(stats.router)

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