"""
email_service.py – Email & webhook notifications.
Sends an email (or fires a webhook) when a secret is viewed.
Runs as a background task so it never blocks the response.
"""
import asyncio
import smtplib
import httpx
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.core.config import get_settings

settings = get_settings()

def _send_smtp(to: str, subject: str, body_html: str) -> None:
    # Blocking SMTP send - call via asyncio.to_thread
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg.attach(MIMEText(body_html, "html"))
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_FROM, to, msg.as_string())

async def notify_secret_viewed(
    secret_id: str,
    notify_email: Optional[str],
    webhook_url: Optional[str],
    actor_ip: Optional[str] = None,
) -> None:
    # Intended to run as a BackgroundTask. Sends email and/or fires the webhook.
    subject = "Your Phantom Share secret was viewed"
    body = f"""
    <html><body>
    <p>Your secret <strong>{secret_id}</strong> was accessed.</p>
    <p>Viewer IP: <code>{actor_ip or 'unknown'}</code></p>
    </body></html>
    """
    tasks = []
    if notify_email and settings.SMTP_USERNAME:
        tasks.append(asyncio.to_thread(_send_smtp, notify_email, subject, body))
    if webhook_url:
        tasks.append(
            _fire_webhook(
                webhook_url,
                {"secret_id": secret_id, "event": "secret_viewed", "actor_ip": actor_ip},
            )
        )
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                print(f"[NOTIFY ERROR] {r}")

async def _fire_webhook(url: str, payload: dict) -> None:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()