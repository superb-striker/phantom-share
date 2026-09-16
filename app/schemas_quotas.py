"""API models owned by per-user quotas."""

from pydantic import BaseModel, Field


class QuotaResponse(BaseModel):
    active_secrets: int
    file_bytes: int
    max_active_secrets: int
    max_file_bytes: int


class QuotaUpdate(BaseModel):
    max_active_secrets: int | None = Field(None, ge=1)
    max_file_bytes: int | None = Field(None, ge=1)
