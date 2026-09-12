"""Send single-use email verification codes."""

import asyncio
import smtplib
from email.message import EmailMessage

from app.core.config import get_settings


def _send(email: str, code: str) -> None:
    settings = get_settings()
    if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        raise RuntimeError("SMTP is not configured")

    message = EmailMessage()
    message["Subject"] = "Verify your Phantom Share email"
    message["From"] = settings.SMTP_FROM
    message["To"] = email
    message.set_content(
        "To verify your email in Phantom Share, enter this code:\n\n"
        f"{code}\n\n"
        "It expires in 15 minutes and can be used once. "
        "If you did not request this, ignore this email."
    )

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
        server.ehlo()
        server.starttls()
        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.send_message(message)


async def send_code(email: str, code: str) -> None:
    await asyncio.to_thread(_send, email, code)
