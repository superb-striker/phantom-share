"""
audit_service.py – Write audit log entries to PostgreSQL.
"""
import json
import logging
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Optional
from uuid import UUID

from app.core.database import get_pool
from app.schemas import AuditAction

logger = logging.getLogger(__name__)

async def log(
    action: str | AuditAction,
    *,
    conn=None,
    actor_id: Optional[UUID] = None,
    actor_ip: Optional[str] = None,
    secret_id: Optional[UUID] = None,
    metadata: Optional[dict] = None,
    severity: str = "info",   # "info" | "warning" | "critical"
) -> None:    
    # Append an audit record. Fails silently so a logging hiccup never breaks the main request.
    meta_payload = {
        **(metadata or {}),
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(), 
    }
    meta_json = json.dumps(meta_payload)
    try:
        if conn:
            # Use the caller's connection - participates in their transaction
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO audit_logs
                        (action, actor_id, actor_ip, secret_id, metadata)
                    VALUES (%s, %s::uuid, %s::inet, %s::uuid, %s::jsonb)
                    """,
                    (action, actor_id, actor_ip, secret_id, meta_json),
                )
        else:
            # Standalone call - open own connection
            async with get_pool().connection() as conn:
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
        # Use structured logging instead of bare print so the message is
        # captured by whatever log aggregator the deployment uses.
        logger.error(
            "[AUDIT ERROR] action=%s actor_id=%s secret_id=%s error=%s",
            action, actor_id, secret_id, exc,
            exc_info=True,
        )        

# these functions prevent forgetting to set severity for high-value events.

async def log_warning(action: str | AuditAction, **kwargs) -> None:
    # Shortcut for severity='warning'
    await log(action, severity="warning", **kwargs)
 
async def log_critical(action: str | AuditAction, **kwargs) -> None:
    # Shortcut for severity='critical'
    await log(action, severity="critical", **kwargs)