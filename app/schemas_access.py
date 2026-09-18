"""API models owned by CIDR and country access policies."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, IPvAnyNetwork, field_validator

from app.schemas import SecretCreate, SecretInfo


def _country_codes(values: list[str]) -> list[str]:
    normalized = list(dict.fromkeys(value.upper() for value in values))
    if any(
        len(value) != 2 or not value.isalpha() or not value.isascii()
        for value in normalized
    ):
        raise ValueError("Countries must be ISO 3166-1 alpha-2 codes")
    return normalized


class SecretCreateWithPolicy(SecretCreate):
    allowed_cidrs: list[IPvAnyNetwork] = Field(default_factory=list, max_length=100)
    allowed_countries: list[str] = Field(default_factory=list, max_length=100)
    location_policy_mode: Literal["all", "any"] = "all"
    geoip_fail_closed: bool = True

    _validate_countries = field_validator("allowed_countries")(_country_codes)


class SecretInfoWithPolicy(SecretInfo):
    current_version: int = 1
    payload_type: str = "text"
    location_restricted: bool = False
    policy_version: int = 1


class LocationPolicyUpdate(BaseModel):
    allowed_cidrs: list[IPvAnyNetwork] = Field(default_factory=list, max_length=100)
    allowed_countries: list[str] = Field(default_factory=list, max_length=100)
    location_policy_mode: Literal["all", "any"] = "all"
    geoip_fail_closed: bool = True

    _validate_countries = field_validator("allowed_countries")(_country_codes)


class LocationPolicyResponse(BaseModel):
    secret_id: UUID
    allowed_cidrs: list[str]
    allowed_countries: list[str]
    location_policy_mode: str
    geoip_fail_closed: bool
    policy_version: int
    signed_token: str
    share_url: str
