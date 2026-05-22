from functools import lru_cache
from typing import List, ClassVar
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Phantom Share"
    APP_VERSION: str = "2.1.0"
    DEBUG: bool = False

    # Database 
    DATABASE_URL: str = "host=localhost dbname=phantom_share user=postgres password=pass123"
    DB_MIN_POOL: int = 2
    DB_MAX_POOL: int = 10

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Encryption 
    CHACHA_KEY_BYTES : ClassVar[int] = 32

    # Master Key Encryption Key – base64-encoded 32-byte secret.
    # Generate with: python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
    SECRET_ENCRYPTION_KEY: str = "generate-and-replace"         
 
    # JWT
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    JWT_SECRET_KEY: str = "generate-and-replace-jwt"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Signed URL tokens
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    SIGNED_URL_SECRET: str = "generate-and-replace-url"
    BASE_URL: str = "http://localhost:8000"   # Used when building share links
    
    # Email/Webhook
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = "name@gmail.com" # replace with email you can send mail from
    '''
    SMTP_PASSWORD must be a Gmail App Password, not your regular Gmail password. - To generate one:
    1) Go to Manage your Google Account -> Security
    2) Make sure 2-Step Verification is on (required)
    3) Search for "App passwords" in the search bar at the top
    4) Choose an app name and enter it
    5) Click Create - you'll get a 16-character password like abcd efgh ijkl mnop
    6) Paste that exactly as SMTP_PASSWORD below
    '''
    SMTP_PASSWORD: str = "generate-and-replace-smtp"  
    SMTP_FROM: str = "name@gmail.com"
    
    # RabbitMQ for email/webhook delivery
    RABBITMQ_URL : str ="amqp://guest:guest@localhost:5672/"
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]
 
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings() -> Settings:
    return Settings()