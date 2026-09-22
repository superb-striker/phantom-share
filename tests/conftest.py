import os
import pathlib
import shutil
import subprocess

import pytest
import pytest_asyncio
from psycopg_pool import AsyncConnectionPool
from redis.asyncio import Redis as AsyncRedis
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

os.environ.setdefault("APP_NAME", "Phantom Share Test")
os.environ.setdefault("APP_VERSION", "test")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "host=localhost dbname=test user=test password=test")
os.environ.setdefault("DB_MIN_POOL", "1")
os.environ.setdefault("DB_MAX_POOL", "5")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SECRET_ENCRYPTION_KEY", "")  # empty -> ephemeral KEK, fine for tests
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-not-for-production")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "15")
os.environ.setdefault("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7")
os.environ.setdefault("SIGNED_URL_SECRET", "test-signed-url-secret")
os.environ.setdefault("BASE_URL", "http://localhost:8000")
os.environ.setdefault("SMTP_HOST", "localhost")
os.environ.setdefault("SMTP_PORT", "587")
os.environ.setdefault("SMTP_USERNAME", "test@example.com")
os.environ.setdefault("SMTP_PASSWORD", "test-password")
os.environ.setdefault("SMTP_FROM", "test@example.com")
os.environ.setdefault("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
os.environ.setdefault("CORS_ORIGINS", '["http://localhost:3000"]')


@pytest.fixture(scope="session")
def redis_container():
    with RedisContainer("redis:8-alpine") as container:
        yield container

@pytest_asyncio.fixture
async def redis_client(redis_container):
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
    client = AsyncRedis.from_url(f"redis://{host}:{port}/0", decode_responses=True)
    yield client
    await client.flushall()
    await client.aclose()


_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


def run_migrations(database_url, command="up"):
    if not shutil.which("dbmate"):
        pytest.fail("dbmate is required for database tests; see README.md")
    migration_env = os.environ.copy()
    migration_env["DATABASE_URL"] = database_url
    subprocess.run(
        ["dbmate", "--env-file", "/dev/null", "--migrations-dir",
         str(_PROJECT_ROOT / "database" / "migrations"),
         "--no-dump-schema", command],
        env=migration_env, check=True, capture_output=True, text=True,
    )

@pytest.fixture(scope="session")
def postgres_container():
    with PostgresContainer("postgres:16-alpine") as container:
        yield container

@pytest_asyncio.fixture
async def db_pool(postgres_container):
    conninfo = postgres_container.get_connection_url().replace("postgresql+psycopg2", "postgresql")
    pool = AsyncConnectionPool(conninfo, min_size=1, max_size=5, open=False)
    await pool.open()
    run_migrations(conninfo + "?sslmode=disable")
    yield pool
    async with pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                """
                TRUNCATE secrets, sessions, users, secret_keys, audit_logs,
                         secret_tracking, secret_views, email_verifications,
                         secret_versions, user_quotas, pending_uploads,
                         object_deletion_outbox, secret_access_policies
                RESTART IDENTITY CASCADE
                """
            )
    await pool.close()
