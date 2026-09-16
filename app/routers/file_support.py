"""Temporary-file helpers shared by file creation and file version routes."""

import os
import tempfile
from pathlib import Path

from fastapi import HTTPException, UploadFile, status

from app.core.config import get_settings

settings = get_settings()


def temp_path(suffix: str = "") -> Path:
    directory = Path(settings.UPLOAD_TEMP_DIR)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix="phantom-", suffix=suffix, dir=directory)
    os.close(fd)
    return Path(name)


def cleanup_paths(*paths: Path) -> None:
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


async def spool_upload(upload: UploadFile) -> tuple[Path, int]:
    path = temp_path(".upload")
    total = 0
    try:
        with path.open("wb") as destination:
            while chunk := await upload.read(1024 * 1024):
                total += len(chunk)
                if total > settings.MAX_FILE_BYTES:
                    raise HTTPException(
                        status.HTTP_413_CONTENT_TOO_LARGE,
                        f"File exceeds {settings.MAX_FILE_BYTES} bytes",
                    )
                destination.write(chunk)
        if total == 0:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "File is empty")
        return path, total
    except Exception:
        cleanup_paths(path)
        raise
