"""API models owned by secret versioning."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas import SecretContent, SecretViewItem


class VersionedSecretContent(SecretContent):
    version: int = 1


class VersionedSecretViewItem(SecretViewItem):
    content_version: int | None = None


class VersionedSecretViewsResponse(BaseModel):
    items: list[VersionedSecretViewItem]
    total: int
    page: int
    page_size: int
    retain_until: datetime


class SecretUpdate(BaseModel):
    content: str = Field(..., min_length=1, max_length=10_000)
    expected_version: int = Field(..., ge=1)
    change_note: str | None = Field(default=None, max_length=500)


class SecretVersionItem(BaseModel):
    version: int
    plaintext_size: int
    created_by: UUID | None
    change_note: str | None
    created_at: datetime
    is_current: bool


class SecretVersionList(BaseModel):
    items: list[SecretVersionItem]
    current_version: int


class SecretUpdateResponse(BaseModel):
    secret_id: UUID
    version: int
    updated_at: datetime
