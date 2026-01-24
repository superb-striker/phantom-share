from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Phantom Share"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    # Database 
    DATABASE_URL: str = "host=localhost dbname=phantom_share user=postgres password=comeback"
    DB_MIN_POOL: int = 2
    DB_MAX_POOL: int = 10

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Encryption 
    # Master Key Encryption Key – base64-encoded 32-byte secret.
    # Generate with: python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
    SECRET_ENCRYPTION_KEY: str = ""          # REQUIRED in production
 
    # JWT
    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Signed URL tokens
    SIGNED_URL_SECRET: str = "change-me-signed-url-secret"
    BASE_URL: str = "http://localhost:8000"   # Used when building share links
    
    # Email/Webhook
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "noreply@phantomshare.io"
 
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings() -> Settings:
    return Settings()