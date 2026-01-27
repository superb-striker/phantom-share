"""
audit_service.py – Write audit log entries to PostgreSQL.
"""
import json
from typing import Optional
from uuid import UUID

from app.core.database import get_pool

async def log(
    action: str,
    *,
    actor_id: Optional[UUID] = None,
    actor_ip: Optional[str] = None,
    secret_id: Optional[UUID] = None,
    metadata: Optional[dict] = None,
    conn=None,
) -> None:    
    # Append an audit record. Fails silently so a logging hiccup never breaks the main request.
    meta_json = json.dumps(metadata or {})
    pool = get_pool()
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO audit_logs
                        (action, actor_id, actor_ip, secret_id, metadata)
                    VALUES (%s, %s::uuid, %s::inet, %s::uuid, %s::jsonb)
                    """,
                    (action, actor_id, actor_ip, secret_id, meta_json),
                )
    except Exception as exc: 
        # Log to stdout but don't crash the caller
        print(f"[AUDIT ERROR] {exc}")