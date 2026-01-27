from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, AnyUrl, model_validator

# Auth

class UserRegister(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8, max_length=128)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds

class RefreshRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    role: str
    is_active: bool
    created_at: datetime

# Secrets

class SecretCreate(BaseModel):
    # Payload to create a new secret
    content: str = Field(..., min_length=1, max_length=10_000)
    ttl_hours: int = Field(default=24, ge=1, le=168)
    password_protected: bool = False
    access_password: Optional[str] = Field(default=None, max_length=128)
    max_views: int = Field(default=1, ge=1, le=100) # Advanced expiry
    # Notifications
    notify_on_view: bool = False
    notify_email: Optional[EmailStr] = None
    webhook_url: Optional[AnyUrl] = Field(default=None, max_length=512)
    # Client-side E2E: if True, `content` is already ciphertext (base64)
    # and `client_nonce` must be supplied. Server will NOT decrypt.
    client_encrypted: bool = False
    client_nonce: Optional[str] = None
    @model_validator(mode="after")
    def validate_password(self):
        if self.password_protected and not self.access_password:
            raise ValueError("access_password is required when password_protected is True")
        if self.client_encrypted and not self.client_nonce:
            raise ValueError("client_nonce is required when client_encrypted is True")
        return self

class SecretCreateResponse(BaseModel):
    secret_id: UUID
    share_url: str
    signed_token: str
    expires_at: datetime
    qr_code: Optional[str] = None

class SecretRetrieve(BaseModel):
    # Body for retrieving a secret (password + optional signed token)
    access_password: Optional[str] = None
    signed_token: Optional[str] = None

class SecretContent(BaseModel):
    content: str
    created_at: datetime
    expires_at: datetime
    views_remaining: Optional[int] = None
    client_encrypted: bool = False  # hint to client to decrypt locally

class SecretInfo(BaseModel):
    # Metadata only – no content
    exists: bool
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    password_protected: bool = False
    viewed: bool = False
    view_count: int = 0
    max_views: int = 1

class SecretListItem(BaseModel):
    id: UUID
    created_at: datetime
    expires_at: datetime
    viewed: bool
    view_count: int
    max_views: int
    password_protected: bool
    notify_on_view: bool

class SecretListResponse(BaseModel):
    items: List[SecretListItem]
    total: int
    page: int
    page_size: int

# Stats

class StatsResponse(BaseModel):
    total_secrets_created: int
    total_secrets_viewed: int
    active_secrets: int
    
# Audit
 
class AuditLogItem(BaseModel):
    id: int
    action: str
    actor_id: Optional[UUID]
    actor_ip: Optional[str]
    secret_id: Optional[UUID]
    metadata: dict
    created_at: datetime
 
class AuditLogResponse(BaseModel):
    items: List[AuditLogItem]
    total: int
    page: int
    page_size: int
 
 # Key management
 
class KeyRotateResponse(BaseModel):
    secret_id: UUID
    new_key_version: int
    rotated_at: datetime