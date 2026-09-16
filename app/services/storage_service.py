"""Private S3-compatible object storage adapter."""

import asyncio
from functools import lru_cache
from pathlib import Path

import boto3

from app.core.config import get_settings

settings = get_settings()


@lru_cache
def _client():
    kwargs = {
        "service_name": "s3",
        "region_name": settings.S3_REGION,
    }
    if settings.S3_ENDPOINT_URL:
        kwargs["endpoint_url"] = settings.S3_ENDPOINT_URL
    if settings.S3_ACCESS_KEY_ID:
        kwargs["aws_access_key_id"] = settings.S3_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = settings.S3_SECRET_ACCESS_KEY
    return boto3.client(**kwargs)


async def upload(path: Path, object_key: str) -> int:
    size = path.stat().st_size
    await asyncio.to_thread(
        _client().upload_file,
        str(path), settings.S3_BUCKET, object_key,
        ExtraArgs={"ServerSideEncryption": "AES256"},
    )
    return size


async def download(object_key: str, destination: Path) -> None:
    await asyncio.to_thread(
        _client().download_file, settings.S3_BUCKET, object_key, str(destination)
    )


async def delete(object_key: str) -> None:
    await asyncio.to_thread(
        _client().delete_object, Bucket=settings.S3_BUCKET, Key=object_key
    )
