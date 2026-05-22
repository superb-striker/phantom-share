"""
notification_service.py – Publishes notification events to RabbitMQ.

Instead of sending email/webhooks inline, we publish a message to the
appropriate RabbitMQ queue and return immediately. The notification_worker
consumes these messages asynchronously with retry + DLQ semantics.
"""
import json
import logging
from typing import Optional

import aio_pika

from app.core.config import get_settings

settings = get_settings()
logger   = logging.getLogger(__name__)

# Exchange and queue names — shared between publisher and worker
NOTIFICATION_EXCHANGE = "phantom.notifications"
EMAIL_QUEUE           = "phantom.email"
WEBHOOK_QUEUE         = "phantom.webhook"
EMAIL_ROUTING_KEY     = "notify.email"
WEBHOOK_ROUTING_KEY   = "notify.webhook"

# Injected by notification_worker once its topology is ready.
# This is just a lightweight reference to the worker's exchange object —
# it does not own a connection.
_exchange: Optional[aio_pika.abc.AbstractExchange] = None


def set_exchange(exchange: aio_pika.abc.AbstractExchange) -> None:
    """
    Hand the worker's exchange to the publisher.
    Called by notification_worker after setup_topology() succeeds.
    """
    global _exchange
    _exchange = exchange
    logger.info("Notification publisher ready (exchange injected by worker)")


def clear_exchange() -> None:
    """
    Drop the exchange reference when the worker shuts down.
    Called by notification_worker in its finally / cleanup path.
    publish() will silently drop messages after this point.
    """
    global _exchange
    _exchange = None
    logger.info("Notification publisher cleared (worker shut down)")


async def publish(routing_key: str, payload: dict) -> None:
    """
    Publish a JSON message to the notification exchange.

    Fails silently with a logged error if the worker has not started yet
    or has already shut down — a notification failure must never propagate
    to the caller (secret retrieval hot path).
    """
    print(f"[PUBLISH] routing_key={routing_key} payload={payload}")
    if _exchange is None:
        logger.error(
            "Notification exchange not available — worker may not have started yet. "
            "Dropping message: routing_key=%s payload=%s", routing_key, payload,
        )
        return
    try:
        await _exchange.publish(
            aio_pika.Message(
                body=json.dumps(payload).encode(),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                content_type="application/json",
            ),
            routing_key=routing_key,
        )
    except Exception as exc:
        # Log and swallow — notification failure must never break secret retrieval
        logger.error(
            "Failed to publish notification: routing_key=%s error=%s payload=%s",
            routing_key, exc, payload,
        )


async def notify_secret_viewed(
    secret_id: str,
    notify_email: Optional[str],
    webhook_url: Optional[str],
    actor_ip: Optional[str] = None,
) -> None:
    """
    Enqueue email and/or webhook notifications for a secret view event.
    Returns immediately — delivery is handled by notification_worker.
    """
    print(f"[NOTIFY] called: email={notify_email}, webhook={webhook_url}, secret={secret_id}")
    ip = actor_ip or "unknown"
    if notify_email:
        if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
            logger.warning(
                "Skipping email notification to %s for secret %s — SMTP not configured",
                notify_email, secret_id,
            )
        else:
            await publish(EMAIL_ROUTING_KEY, {
                "to":        notify_email,
                "secret_id": secret_id,
                "actor_ip":  ip,
            })
    if webhook_url:
        await publish(WEBHOOK_ROUTING_KEY, {
            "url":       webhook_url,
            "secret_id": secret_id,
            "event":     "secret_viewed",
            "actor_ip":  ip,
        })