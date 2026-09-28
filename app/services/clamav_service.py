"""Minimal async client for clamd's framed INSTREAM protocol."""

import asyncio
import struct
from pathlib import Path
from opentelemetry import trace
from opentelemetry.trace import SpanKind

from app.core.config import get_settings

settings = get_settings()
tracer = trace.get_tracer("phantom.clamav")


async def scan(path: Path) -> tuple[str, str]:
    with tracer.start_as_current_span(
        "clamav.scan",
        kind=SpanKind.CLIENT,
        attributes={
            "server.address": settings.CLAMAV_HOST,
            "server.port": settings.CLAMAV_PORT,
        },
        record_exception=True,
        set_status_on_exception=True,
    ) as span:
        result = await _scan(path)
        span.set_attribute("clamav.scan.status", result[0])
        return result


async def _scan(path: Path) -> tuple[str, str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(settings.CLAMAV_HOST, settings.CLAMAV_PORT),
            timeout=settings.CLAMAV_TIMEOUT_SECONDS,
        )
        writer.write(b"zINSTREAM\0")
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                writer.write(struct.pack(">I", len(chunk)))
                writer.write(chunk)
                await writer.drain()
        writer.write(struct.pack(">I", 0))
        await writer.drain()
        reply = await asyncio.wait_for(
            reader.readuntil(b"\0"), timeout=settings.CLAMAV_TIMEOUT_SECONDS
        )
        writer.close()
        await writer.wait_closed()
    except Exception as exc:
        raise RuntimeError("Virus scanner unavailable") from exc

    result = reply.rstrip(b"\0").decode("utf-8", "replace")
    if result.endswith(" OK"):
        return "clean", result
    if result.endswith(" FOUND"):
        return "infected", result
    raise RuntimeError(f"Virus scanner returned an indeterminate result: {result}")
