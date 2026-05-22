"""
notification_worker.py – Consumes notification events from RabbitMQ.
"""
import asyncio
import json
import logging
import smtplib
import aio_pika
import httpx
from typing import Optional
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import get_settings
from app.services.notification_service import (
    EMAIL_QUEUE,
    EMAIL_ROUTING_KEY,
    NOTIFICATION_EXCHANGE,
    WEBHOOK_QUEUE,
    WEBHOOK_ROUTING_KEY,
    set_exchange,
    clear_exchange,
)

settings = get_settings()
logger   = logging.getLogger(__name__)

EMAIL_DLQ           = "phantom.email.dlq"
WEBHOOK_DLQ         = "phantom.webhook.dlq"
DLX                 = "phantom.dlx"
MAX_RETRIES         = 3
RETRY_BASE_DELAY    = 1   
RETRY_LOOP_INTERVAL = 30  

_stop_event: Optional[asyncio.Event] = None


async def setup_topology(
    channel: aio_pika.abc.AbstractChannel,
) -> aio_pika.abc.AbstractExchange:
    """Declare the full exchange + queue topology idempotently."""
    exchange = await channel.declare_exchange(
        NOTIFICATION_EXCHANGE,
        aio_pika.ExchangeType.DIRECT,
        durable=True,
    )
    dlx = await channel.declare_exchange(
        DLX,
        aio_pika.ExchangeType.DIRECT,
        durable=True,
    )
    def dlq_args(dlq_name: str) -> dict:
        return {
            "x-dead-letter-exchange":    DLX,
            "x-dead-letter-routing-key": dlq_name,
        }
    email_queue = await channel.declare_queue(
        EMAIL_QUEUE, durable=True, arguments=dlq_args(EMAIL_DLQ)
    )
    webhook_queue = await channel.declare_queue(
        WEBHOOK_QUEUE, durable=True, arguments=dlq_args(WEBHOOK_DLQ)
    )
    await email_queue.bind(exchange,   routing_key=EMAIL_ROUTING_KEY)
    await webhook_queue.bind(exchange, routing_key=WEBHOOK_ROUTING_KEY)
    email_dlq   = await channel.declare_queue(EMAIL_DLQ,   durable=True)
    webhook_dlq = await channel.declare_queue(WEBHOOK_DLQ, durable=True)
    await email_dlq.bind(dlx,   routing_key=EMAIL_DLQ)
    await webhook_dlq.bind(dlx, routing_key=WEBHOOK_DLQ)
    return exchange


def build_email(to: str, secret_id: str, actor_ip: str) -> MIMEMultipart:
    msg            = MIMEMultipart("alternative")
    msg["Subject"] = "Your Phantom Share secret was viewed"
    msg["From"]    = settings.SMTP_FROM
    msg["To"]      = to
    body = f"""
    <html><body>
      <p>Your secret <strong>{secret_id}</strong> was accessed.</p>
      <p>Viewer IP: <code>{actor_ip}</code></p>
      <p>If this was unexpected, consider revoking further access.</p>
    </body></html>
    """
    msg.attach(MIMEText(body, "html"))
    return msg


def send_smtp(to: str, secret_id: str, actor_ip: str) -> None:
    print(f"[SMTP] sending to={to} host={settings.SMTP_HOST}:{settings.SMTP_PORT}")
    msg = build_email(to, secret_id, actor_ip)
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_FROM, to, msg.as_string())


async def handle_email(message: aio_pika.abc.AbstractIncomingMessage) -> None:
    print(f"[HANDLE_EMAIL] received message")
    async with message.process(requeue=False):
        payload = json.loads(message.body)
        await asyncio.to_thread(
            send_smtp,
            payload["to"],
            payload["secret_id"],
            payload["actor_ip"],
        )
        logger.info(
            "Email notification sent: to=%s secret_id=%s",
            payload["to"], payload["secret_id"],
        )


async def handle_webhook(message: aio_pika.abc.AbstractIncomingMessage) -> None:
    async with message.process(requeue=False):
        payload = json.loads(message.body)
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(payload["url"], json={
                "secret_id": payload["secret_id"],
                "event":     payload["event"],
                "actor_ip":  payload["actor_ip"],
            })
            resp.raise_for_status()
        logger.info(
            "Webhook fired: url=%s secret_id=%s status=%s",
            payload["url"], payload["secret_id"], resp.status_code,
        )


async def retry_loop(
    channel:  aio_pika.abc.AbstractChannel,
    exchange: aio_pika.abc.AbstractExchange,
) -> None:
    """Polls both DLQs. FIXED: Uses get_queue to avoid re-declaration conflicts."""
    email_dlq   = await channel.get_queue(EMAIL_DLQ)
    webhook_dlq = await channel.get_queue(WEBHOOK_DLQ)
    while not _stop_event.is_set(): # type: ignore
        await asyncio.sleep(RETRY_LOOP_INTERVAL)
        for dlq, routing_key in [
            (email_dlq,   EMAIL_ROUTING_KEY),
            (webhook_dlq, WEBHOOK_ROUTING_KEY),
        ]:
            while True:
                message = await dlq.get(no_ack=False, fail=False)
                if message is None:
                    break
                headers = message.headers or {}
                attempt = int(str(headers.get("x-retry-attempt", 0))) + 1
                delay   = RETRY_BASE_DELAY * (2 ** (attempt - 1))  
                if attempt > MAX_RETRIES:
                    await message.ack()
                    fire_critical_alert(message.body, routing_key, attempt)
                    continue
                logger.warning(
                    "Retrying failed notification: attempt=%d/%d queue=%s",
                    attempt, MAX_RETRIES, routing_key,
                )
                await asyncio.sleep(delay)
                retry_msg = aio_pika.Message(
                    body=message.body,
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                    content_type="application/json",
                    headers={**headers, "x-retry-attempt": attempt},
                )
                await exchange.publish(retry_msg, routing_key=routing_key)
                await message.ack()


def fire_critical_alert(body: bytes, routing_key: str, attempts: int) -> None:
    try:
        payload = json.loads(body)
    except Exception:
        payload = {"raw": body.decode(errors="replace")}
    logger.critical(
        "Notification permanently failed after %d attempts — "
        "manual investigation required. queue=%s payload=%s",
        attempts, routing_key, payload,
    )


async def notification_worker(ready_event: Optional[asyncio.Event] = None) -> None:
    """Worker entrypoint. FIXED: Uses get_queue and triggers startup synchronization event."""
    global _stop_event
    _stop_event = asyncio.Event()   
    connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=10)
        exchange = await setup_topology(channel)
        set_exchange(exchange)
        
        email_queue   = await channel.get_queue(EMAIL_QUEUE)
        webhook_queue = await channel.get_queue(WEBHOOK_QUEUE)
        await email_queue.consume(handle_email)
        await webhook_queue.consume(handle_webhook)
        
        logger.info("Notification worker started - consuming email + webhook queues")
        if ready_event:
            ready_event.set()
            
        stop_waiter = asyncio.ensure_future(_stop_event.wait())
        await asyncio.gather(
            stop_waiter,
            retry_loop(channel, exchange),
            return_exceptions=True,
        )
        clear_exchange()
    logger.info("Notification worker shut down")


async def stop_worker() -> None:
    if _stop_event is not None:
        _stop_event.set()