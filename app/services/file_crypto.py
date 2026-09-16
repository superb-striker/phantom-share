"""Bounded-memory authenticated encryption for file objects."""

import hashlib
import os
import struct
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC = b"PHANTOM1"
CHUNK_SIZE = 1024 * 1024


def encrypt_file(source: Path, destination: Path, dek: bytes, secret_id: UUID, version: int) -> tuple[int, str]:
    cipher = ChaCha20Poly1305(dek)
    nonce_prefix = os.urandom(8)
    digest = hashlib.sha256()
    total = 0
    aad_prefix = secret_id.bytes + struct.pack(">I", version)
    with source.open("rb") as src, destination.open("wb") as dst:
        dst.write(MAGIC + nonce_prefix + struct.pack(">I", CHUNK_SIZE))
        index = 0
        while chunk := src.read(CHUNK_SIZE):
            digest.update(chunk)
            total += len(chunk)
            nonce = nonce_prefix + struct.pack(">I", index)
            encrypted = cipher.encrypt(nonce, chunk, aad_prefix + struct.pack(">I", index))
            dst.write(struct.pack(">I", len(encrypted)))
            dst.write(encrypted)
            index += 1
    return total, digest.hexdigest()


def decrypt_file(source: Path, destination: Path, dek: bytes, secret_id: UUID, version: int) -> None:
    cipher = ChaCha20Poly1305(dek)
    aad_prefix = secret_id.bytes + struct.pack(">I", version)
    with source.open("rb") as src, destination.open("wb") as dst:
        header = src.read(len(MAGIC) + 12)
        if len(header) != len(MAGIC) + 12 or header[:len(MAGIC)] != MAGIC:
            raise ValueError("Invalid encrypted file header")
        nonce_prefix = header[len(MAGIC):len(MAGIC) + 8]
        index = 0
        while True:
            raw_length = src.read(4)
            if not raw_length:
                break
            if len(raw_length) != 4:
                raise ValueError("Truncated encrypted file")
            length = struct.unpack(">I", raw_length)[0]
            encrypted = src.read(length)
            if len(encrypted) != length:
                raise ValueError("Truncated encrypted file")
            nonce = nonce_prefix + struct.pack(">I", index)
            plaintext = cipher.decrypt(
                nonce, encrypted, aad_prefix + struct.pack(">I", index)
            )
            dst.write(plaintext)
            index += 1
