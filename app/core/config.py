from functools import lru_cache
from typing import List, ClassVar
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    APP_NAME: str 
    APP_VERSION: str
    DEBUG: bool

    # Database 
    DATABASE_URL: str    
    DB_MIN_POOL: int
    DB_MAX_POOL: int

    # Redis
    REDIS_URL: str

    # Encryption 
    CHACHA_KEY_BYTES : int 

    # Master Key Encryption Key – base64-encoded 32-byte secret.
    # Generate with: python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
    SECRET_ENCRYPTION_KEY: str      
 
    # JWT
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    JWT_SECRET_KEY: str 
    JWT_ALGORITHM: str
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int

    # Signed URL tokens
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    SIGNED_URL_SECRET: str
    BASE_URL: str           # Used when building share links
    
    # Email/Webhook
    SMTP_HOST: str 
    SMTP_PORT: int 
    SMTP_USERNAME: str  # replace with email you can send mail from
    '''
    SMTP_PASSWORD must be a Gmail App Password, not your regular Gmail password. - To generate one:
    1) Go to Manage your Google Account -> Security
    2) Make sure 2-Step Verification is on (required)
    3) Search for "App passwords" in the search bar at the top
    4) Choose an app name and enter it
    5) Click Create - you'll get a 16-character password like abcd efgh ijkl mnop
    6) Paste that exactly as SMTP_PASSWORD below
    '''
    SMTP_PASSWORD: str 
    SMTP_FROM: str 

    # RabbitMQ for email/webhook delivery
    RABBITMQ_URL : str
    
    # CORS
    CORS_ORIGINS: List[str] 
 
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings() -> Settings:
    return Settings()
