"""
helper.py – Low-level cryptography utilities.

Design:
  - A Master Key Encryption Key (KEK) lives in the environment.
  - For each secret, a fresh Data Encryption Key (DEK) is generated.
  - The DEK is used to encrypt the secret content (ChaCha20-Poly1305).
  - The DEK itself is wrapped (encrypted) with the KEK before storage.
  - The server therefore never stores a plaintext DEK.

Client-side E2E flow (optional):
  - Client encrypts content before POST; server stores opaque ciphertext.
  - The endpoint simply records the ciphertext + nonce; no DEK is generated.
"""
import base64
import io
import os
import logging

import qrcode
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from app.core.config import get_settings

settings = get_settings()

# Master KEK 
logger = logging.getLogger(__name__)

def _load_kek() -> bytes:
    raw = settings.SECRET_ENCRYPTION_KEY
    if raw:
        key = base64.b64decode(raw)
        if len(key) != settings.CHACHA_KEY_BYTES:
            raise ValueError(
                f"SECRET_ENCRYPTION_KEY must decode to {settings.CHACHA_KEY_BYTES} bytes; "
                f"got {len(key)}"
            )
        return key
    key = ChaCha20Poly1305.generate_key()
    logger.warning(
        "No SECRET_ENCRYPTION_KEY set - using ephemeral KEK. "
        "Data will not survive restart. Set this in production. "
        "Ephemeral KEK: %s",
        base64.b64encode(key).decode(),
    )
    return key

_kek: bytes = _load_kek()
_kek_chacha = ChaCha20Poly1305(_kek)


# DEK management 

def generate_dek() -> bytes:
    return ChaCha20Poly1305.generate_key()

def wrap_dek(dek: bytes) -> tuple[str, str]:
    """Encrypt DEK with the master KEK. Returns (wrapped_dek_b64, nonce_b64)"""
    nonce = os.urandom(12)
    wrapped = _kek_chacha.encrypt(nonce, dek, None)
    return base64.b64encode(wrapped).decode(), base64.b64encode(nonce).decode()

def unwrap_dek(wrapped_dek_b64: str, nonce_b64: str) -> bytes:
    """Decrypt a wrapped DEK using the master KEK.
    Raises:
        ValueError: if authentication fails (wrong key or tampered data).
    """
    wrapped = base64.b64decode(wrapped_dek_b64)
    nonce = base64.b64decode(nonce_b64)
    try:
        return _kek_chacha.decrypt(nonce, wrapped, None)
    except Exception as exc:
        raise ValueError("DEK unwrap failed - wrong KEK or corrupt data") from exc


# Content encryption (server-managed key) 

def encrypt_content(content: str, dek: bytes) -> tuple[str, str]:
    '''Encrypt plaintext with the given DEK. Returns (ciphertext_b64, nonce_b64)'''
    chacha = ChaCha20Poly1305(dek)
    nonce = os.urandom(12)
    encrypted = chacha.encrypt(nonce, content.encode(), None)
    return base64.b64encode(encrypted).decode(), base64.b64encode(nonce).decode()

def decrypt_content(encrypted_b64: str, nonce_b64: str, dek: bytes) -> str:
    """Decrypt ciphertext with the given DEK.
    Raises:
        ValueError: if authentication fails.
    """
    chacha = ChaCha20Poly1305(dek)
    encrypted = base64.b64decode(encrypted_b64)
    nonce = base64.b64decode(nonce_b64)
    try:
        return chacha.decrypt(nonce, encrypted, None).decode()
    except Exception as exc:
        raise ValueError("Content decryption failed") from exc

def validate_client_encrypted(ciphertext_b64: str, nonce_b64: str) -> None:
    """Validate that client-supplied ciphertext and nonce are well-formed base64.
    Raises:
        ValueError: on malformed input.
    """
    try:
        nonce = base64.b64decode(nonce_b64, validate=True)
    except Exception:
        raise ValueError("nonce_b64 is not valid base64")
    if len(nonce) != 12:
        raise ValueError(f"nonce must be 12 bytes; got {len(nonce)}")
    try:
        base64.b64decode(ciphertext_b64, validate=True)
    except Exception:
        raise ValueError("ciphertext_b64 is not valid base64")

# QR codes 

def generate_qr_code(url: str) -> str:
    """Returns a base64-encoded PNG QR code for the given URL."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    try:
        img.save(buf, "PNG")
        return base64.b64encode(buf.getvalue()).decode()
    finally:
        buf.close()