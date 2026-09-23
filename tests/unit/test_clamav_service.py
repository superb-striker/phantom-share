import asyncio
import struct

import pytest

from app.services import clamav_service


async def _clamd(reader, writer, reply):
    assert await reader.readexactly(len(b"zINSTREAM\0")) == b"zINSTREAM\0"
    received = bytearray()
    while True:
        size = struct.unpack(">I", await reader.readexactly(4))[0]
        if size == 0:
            break
        received.extend(await reader.readexactly(size))
    assert received == b"file contents"
    writer.write(reply + b"\0")
    await writer.drain()
    writer.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (b"stream: OK", "clean"),
        (b"stream: Eicar-Signature FOUND", "infected"),
    ],
)
async def test_scan_uses_clamd_instream_protocol(tmp_path, monkeypatch, reply, expected):
    server = await asyncio.start_server(
        lambda reader, writer: _clamd(reader, writer, reply), "127.0.0.1", 0
    )
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setattr(clamav_service.settings, "CLAMAV_HOST", "127.0.0.1")
    monkeypatch.setattr(clamav_service.settings, "CLAMAV_PORT", port)
    path = tmp_path / "upload"
    path.write_bytes(b"file contents")
    try:
        status, detail = await clamav_service.scan(path)
    finally:
        server.close()
        await server.wait_closed()
    assert status == expected
    assert reply.decode() in detail


@pytest.mark.asyncio
async def test_scan_fails_closed_when_clamd_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(clamav_service.settings, "CLAMAV_HOST", "127.0.0.1")
    monkeypatch.setattr(clamav_service.settings, "CLAMAV_PORT", 1)
    path = tmp_path / "upload"
    path.write_bytes(b"file contents")
    with pytest.raises(RuntimeError, match="scanner unavailable"):
        await clamav_service.scan(path)
