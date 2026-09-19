"""Owner-managed CIDR and country policy routes for secrets."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.config import get_settings
from app.core.permissions import require_owns_secret, require_user
from app.core.security import create_signed_token
from app.schemas_access import LocationPolicyResponse, LocationPolicyUpdate
from app.services import audit_service

settings = get_settings()
router = APIRouter(tags=["secret access policies"])


def _get_pool():
    # Resolve through the parent router to retain its test injection point.
    from app.routers import secrets

    return secrets.get_pool()


@router.put("/{secret_id}/access-policy", response_model=LocationPolicyResponse)
async def update_location_policy(
    secret_id: UUID,
    body: LocationPolicyUpdate,
    request: Request,
    current_user: dict = Depends(require_user),
):
    async with _get_pool().connection() as conn, conn.transaction():
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT s.owner_id, s.expires_at, s.payload_type, p.policy_version
                    FROM secrets s JOIN secret_access_policies p ON p.secret_id = s.id
                    WHERE s.id = %s FOR UPDATE OF s, p
                    """,
                    (secret_id,),
                )
                secret = await cur.fetchone()
                if not secret:
                    raise HTTPException(status.HTTP_404_NOT_FOUND, "Secret not found")
                require_owns_secret(str(secret[0]) if secret[0] else None, current_user)
                new_policy_version = secret[3] + 1
                await cur.execute(
                    """
                    UPDATE secret_access_policies SET
                        allowed_cidrs = %s::cidr[],
                        allowed_countries = %s::char(2)[],
                        location_policy_mode = %s,
                        geoip_fail_closed = %s,
                        policy_version = %s,
                        updated_at = clock_timestamp()
                    WHERE secret_id = %s
                    """,
                    (
                        [str(value) for value in body.allowed_cidrs],
                        body.allowed_countries,
                        body.location_policy_mode,
                        body.geoip_fail_closed,
                        new_policy_version,
                        secret_id,
                    ),
                )
                token = create_signed_token(
                    secret_id,
                    0,
                    new_policy_version,
                    expires_at=secret[1],
                )
                await cur.execute(
                    """
                    UPDATE secrets
                    SET signed_token = %s, updated_at = clock_timestamp()
                    WHERE id = %s
                    """,
                    (token, secret_id),
                )
            await audit_service.log(
                "secret_updated",
                conn=conn,
                actor_id=UUID(current_user["id"]),
                actor_ip=request.state.client_ip,
                secret_id=secret_id,
                metadata={
                    "change": "location_policy",
                    "policy_version": new_policy_version,
                },
            )
    suffix = "/file" if secret[2] == "file" else ""
    share_url = f"{settings.BASE_URL}/api/secrets/{secret_id}{suffix}?token={token}"
    return LocationPolicyResponse(
        secret_id=secret_id,
        allowed_cidrs=[str(value) for value in body.allowed_cidrs],
        allowed_countries=body.allowed_countries,
        location_policy_mode=body.location_policy_mode,
        geoip_fail_closed=body.geoip_fail_closed,
        policy_version=new_policy_version,
        signed_token=token,
        share_url=share_url,
    )
