"""CIDR and local GeoIP country access-policy evaluation."""

from functools import lru_cache
from ipaddress import ip_address, ip_network
from pathlib import Path
from uuid import UUID

import geoip2.database
from fastapi import HTTPException, status
from geoip2.errors import AddressNotFoundError

from app.core.client_ip import normalize_ip
from app.core.config import get_settings
from app.core.database import get_pool
from app.core.security import verify_signed_token
from app.services import audit_service


@lru_cache(maxsize=2)
def _reader(path: str, modified_ns: int):
    return geoip2.database.Reader(path)


def country_for_ip(client_ip: str) -> str | None:
    path = get_settings().GEOIP_DATABASE_PATH
    database = Path(path)
    if not path or not database.is_file():
        return None
    try:
        return _reader(path, database.stat().st_mtime_ns).country(client_ip).country.iso_code
    except (AddressNotFoundError, ValueError):
        return None


def evaluate(
    client_ip: str,
    allowed_cidrs: list[str],
    allowed_countries: list[str],
    mode: str,
    geoip_fail_closed: bool,
) -> tuple[bool, str | None, str | None]:
    """Return (allowed, country, denial_reason)."""
    if not allowed_cidrs and not allowed_countries:
        return True, None, None
    try:
        normalized = normalize_ip(client_ip)
        address = ip_address(normalized)
    except ValueError:
        return False, None, "CLIENT_IP_INVALID"

    checks: list[bool] = []
    if allowed_cidrs:
        checks.append(any(address in ip_network(value, strict=False) for value in allowed_cidrs))

    country = None
    if allowed_countries:
        country = country_for_ip(normalized)
        if country is None and geoip_fail_closed:
            return False, None, "GEOIP_LOOKUP_FAILED"
        checks.append(country in allowed_countries if country else True)

    allowed = all(checks) if mode == "all" else any(checks)
    if allowed:
        return True, country, None
    if allowed_cidrs and allowed_countries:
        reason = "LOCATION_NOT_ALLOWED"
    elif allowed_cidrs:
        reason = "CIDR_NOT_ALLOWED"
    else:
        reason = "COUNTRY_NOT_ALLOWED"
    return False, country, reason


async def authorize(secret_id: UUID, token: str | None, client_ip: str) -> int:
    """Validate token policy version and location before a view is consumed."""
    async with get_pool().connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """
            SELECT p.allowed_cidrs::text[], p.allowed_countries::text[],
                    p.location_policy_mode, p.geoip_fail_closed, p.policy_version
            FROM secret_access_policies p WHERE p.secret_id = %s
            """,
            (secret_id,),
        )
        row = await cur.fetchone()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
    if token and UUID(verify_signed_token(token, row[5])) != secret_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Share token does not match this secret")
    allowed, country, reason = evaluate(
        client_ip, list(row[0]), [value.strip() for value in row[1]],
        row[2], row[3],
    )
    if not allowed:
        await audit_service.log_warning(
            "invalid_token", secret_id=secret_id, actor_ip=client_ip,
            metadata={
                "reason": reason, "country": country,
                "policy_version": row[4],
            },
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"error_code": reason, "message": "Access from this location is not allowed"},
        )
    return row[4]
