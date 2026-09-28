from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App
    APP_NAME: str 
    APP_VERSION: str
    DEBUG: bool

    # Database 
    DATABASE_URL: str    
    DB_MIN_POOL: int
    DB_MAX_POOL: int

    VIEW_HISTORY_RETENTION_DAYS: int = Field(default=30, ge=1, le=365)
    MAX_SECRET_VERSIONS: int = Field(default=100, ge=1, le=1000)
    MAX_FILE_BYTES: int = Field(default=52_428_800, ge=1)
    DEFAULT_MAX_ACTIVE_SECRETS: int = Field(default=100, ge=1)
    DEFAULT_MAX_FILE_STORAGE_BYTES: int = Field(default=1_073_741_824, ge=1)
    UPLOAD_TEMP_DIR: str = "/tmp/phantom-uploads"

    # Redis
    REDIS_URL: str

    # S3-compatible encrypted file storage
    S3_BUCKET: str = "phantom-share"
    S3_REGION: str = "us-east-1"
    S3_ENDPOINT_URL: str = ""
    S3_ACCESS_KEY_ID: str = ""
    S3_SECRET_ACCESS_KEY: str = ""

    # ClamAV daemon (private network only)
    CLAMAV_HOST: str = "clamav"
    CLAMAV_PORT: int = 3310
    CLAMAV_TIMEOUT_SECONDS: int = 60

    # Network/location access controls. Forwarded headers are trusted only
    # when the direct socket peer belongs to one of these networks.
    TRUSTED_PROXY_CIDRS: list[str] = Field(default_factory=list)
    GEOIP_DATABASE_PATH: str = ""

    # OpenTelemetry. Standard OTLP headers, certificates, compression, and
    # batch-processor settings continue to come from OTEL_* environment vars.
    OTEL_ENABLED: bool = True
    OTEL_SERVICE_NAME: str = "phantom-share"
    OTEL_DEPLOYMENT_ENVIRONMENT: str = "development"
    OTEL_TRACES_EXPORTER: str = "otlp"
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"
    OTEL_EXPORTER_OTLP_INSECURE: bool = True
    OTEL_TRACE_SAMPLE_RATIO: float = Field(default=1.0, ge=0.0, le=1.0)
    OTEL_EXCLUDED_URLS: str = "/health"

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
    CORS_ORIGINS: list[str] 
 
    model_config = SettingsConfigDict(
        env_file = ".env",
        env_file_encoding = "utf-8",
        extra = "ignore"
    )

@lru_cache
def get_settings() -> Settings:
    return Settings()
