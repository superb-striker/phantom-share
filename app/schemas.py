from datetime import datetime
from enum import StrEnum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, AnyUrl, model_validator

# Enums

class UserRole(StrEnum):
    ADMIN    = "admin"
    USER     = "user"
    READONLY = "readonly"
    
class AuditAction(StrEnum):
    # Auth
    USER_REGISTERED = "user_registered"
    USER_LOGIN      = "user_login"
    USER_LOGOUT     = "user_logout"
    TOKEN_REFRESH   = "token_refresh"
    # Secrets
    SECRET_CREATED  = "secret_created"
    SECRET_VIEWED   = "secret_viewed"
    SECRET_DELETED  = "secret_deleted"
    SECRET_EXPIRED  = "secret_expired"
    KEY_ROTATED     = "key_rotated"
    # Admin
    USER_REMOVED       = "user_removed"
    ADMIN_ROLE_CHANGE  = "admin_role_change"
    ADMIN_USER_TOGGLE  = "admin_user_toggle"
    ADMIN_CLEANUP      = "admin_cleanup"
    # Security
    RATE_LIMIT_HIT = "rate_limit_hit"
    INVALID_TOKEN  = "invalid_token"
 
class AuditSeverity(StrEnum):
    INFO     = "info"
    WARNING  = "warning"
    CRITICAL = "critical"


# Auth

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires

class RefreshRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    role: str
    is_active: bool
    created_at: datetime
    
# Admin

class AdminUserResponse(BaseModel):
    id:           UUID
    email:        str
    username:     str
    role:         UserRole
    is_active:    bool
    created_at:   datetime
    updated_at:   datetime
    delete_after: Optional[datetime] = None
 
class AdminUserListResponse(BaseModel):
    items:     List[AdminUserResponse]
    total:     int
    page:      int
    page_size: int
 
class RoleUpdateRequest(BaseModel):
    role: UserRole
 
class UserStatusResponse(BaseModel):
    user_id:      UUID
    is_active:    bool
    delete_after: Optional[datetime] = None
    
class CleanupResponse(BaseModel):
    secrets_deleted:  int
    sessions_deleted: int
    users_deleted:    int
    ran_at:           datetime

# Secrets

class SecretCreate(BaseModel):
    # Payload to create a new secret
    content: str = Field(..., min_length=1, max_length=10_000)
    ttl_hours: int = Field(default=24, ge=1, le=168)
    password_protected: bool = False
    access_password: Optional[str] = Field(default=None, min_length=4, max_length=128)
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
    def check_consistency(self) -> "SecretCreate":
        if self.notify_on_view and not self.notify_email:
            raise ValueError("notify_email is required when notify_on_view is True")
        if self.password_protected and not self.access_password:
            raise ValueError("access_password is required when password_protected is True")
        if not self.password_protected and self.access_password:
            raise ValueError("Set password_protected=True when supplying an access_password")
        if self.client_encrypted and not self.client_nonce:
            raise ValueError("client_nonce is required when client_encrypted is True")
        return self

class SecretCreateResponse(BaseModel):
    secret_id: UUID
    share_url: str
    signed_token: str
    expires_at: datetime
    qr_code: Optional[str] = None

class SecretRetrieveRequest(BaseModel):
    # Body for retrieving a secret (password + optional signed token)
    access_password: Optional[str] = None
    signed_token: Optional[str] = None

class SecretContent(BaseModel):
    content: str
    created_at: datetime
    expires_at: datetime
    views_remaining: Optional[int] = None
    client_encrypted: bool = False  # client to decrypt locally

class SecretInfo(BaseModel):
    # Metadata only – no content
    exists: bool
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    password_protected: bool
    viewed: bool
    view_count: int
    max_views: int

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
    severity: AuditSeverity = AuditSeverity.INFO 

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
    
# Generic

class MessageResponse(BaseModel):
    # Generic success acknowledgement - e.g. {'message': 'ok'}.
    message: str
 
class ErrorResponse(BaseModel):
    # Standardised error envelope returned by FastAPI exception handlers
    detail:     str
    error_code: Optional[str] = None   # e.g. "SECRET_NOT_FOUND", "RATE_LIMITED"
