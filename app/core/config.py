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
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings() -> Settings:
    return Settings()