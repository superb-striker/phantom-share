"""Creator-facing access history for email-restricted secrets."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import get_current_user
from app.routers import secrets
from app.schemas_versioning import (
    VersionedSecretViewItem as SecretViewItem,
)
from app.schemas_versioning import (
    VersionedSecretViewsResponse as SecretViewsResponse,
)

router = APIRouter(tags=["secret views"])


def _get_pool():
    # Resolve through the parent router to retain its test injection point.
    return secrets.get_pool()


@router.get("/{secret_id}/views", response_model=SecretViewsResponse)
async def secret_views(
    secret_id: UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    """Return durable retrieval history to the secret's creator."""
    async with _get_pool().connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """
            SELECT retain_until FROM secret_tracking
            WHERE secret_id = %s AND owner_id = %s
                AND retain_until > clock_timestamp()
            """,
            (secret_id, current_user["id"]),
        )
        tracking = await cur.fetchone()
        if not tracking:
            # Avoid revealing whether another user's tracking record exists.
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "View history not found",
            )

        await cur.execute(
            "SELECT COUNT(*) FROM secret_views WHERE secret_id = %s",
            (secret_id,),
        )

        row = await cur.fetchone()
        if not row:
            raise HTTPException(
                status.HTTP_204_NO_CONTENT,
                "No views for the secret"
            )
        total = row[0]
        await cur.execute(
            """
            SELECT id, viewer_id, viewer_email, email_verified, viewed_at, content_version
            FROM secret_views
            WHERE secret_id = %s
            ORDER BY viewed_at DESC, id DESC
            LIMIT %s OFFSET %s
            """,
            (secret_id, page_size, (page - 1) * page_size),
        )
        rows = await cur.fetchall()

    return SecretViewsResponse(
        items=[
            SecretViewItem(
                id=row[0],
                viewer_id=row[1],
                viewer_email=row[2],
                email_verified=row[3],
                viewed_at=row[4],
                content_version=row[5],
            )
            for row in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
        retain_until=tracking[0],
    )
