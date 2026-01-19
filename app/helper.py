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
import secrets
import string

import qrcode
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from app.core.config import get_settings

settings = get_settings()

# Master KEK 
def _load_kek() -> bytes:
    raw = settings.SECRET_ENCRYPTION_KEY
    if raw:
        return base64.b64decode(raw)
    # Dev fallback - generate ephemeral key (data will not survive restart)
    key = ChaCha20Poly1305.generate_key()
    print(
        f"[WARNING] No SECRET_ENCRYPTION_KEY set. "
        f"Generated ephemeral KEK: {base64.b64encode(key).decode()}"
    )
    return key

_kek: bytes = _load_kek()
_kek_chacha = ChaCha20Poly1305(_kek)


# Helpers 

def generate_secret_id(length: int = 12) -> str:
    # URL-safe random identifier
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# DEK management 

def generate_dek() -> bytes:
    return ChaCha20Poly1305.generate_key()

def wrap_dek(dek: bytes) -> tuple[str, str]:
    # Encrypt DEK with the master KEK. Returns (wrapped_dek_b64, nonce_b64)
    nonce = os.urandom(12)
    wrapped = _kek_chacha.encrypt(nonce, dek, None)
    return base64.b64encode(wrapped).decode(), base64.b64encode(nonce).decode()

def unwrap_dek(wrapped_dek_b64: str, nonce_b64: str) -> bytes:
    # Decrypt the DEK using the master KEK
    wrapped = base64.b64decode(wrapped_dek_b64)
    nonce = base64.b64decode(nonce_b64)
    return _kek_chacha.decrypt(nonce, wrapped, None)


# Content encryption (server-managed key) 

def encrypt_content(content: str, dek: bytes) -> tuple[str, str]:
    # Encrypt plaintext with the given DEK
    # Returns (ciphertext_b64, nonce_b64)
    chacha = ChaCha20Poly1305(dek)
    nonce = os.urandom(12)
    encrypted = chacha.encrypt(nonce, content.encode(), None)
    return base64.b64encode(encrypted).decode(), base64.b64encode(nonce).decode()

def decrypt_content(encrypted_b64: str, nonce_b64: str, dek: bytes) -> str:
    # Decrypt ciphertext with the given DEK
    chacha = ChaCha20Poly1305(dek)
    encrypted = base64.b64decode(encrypted_b64)
    nonce = base64.b64decode(nonce_b64)
    return chacha.decrypt(nonce, encrypted, None).decode()


# Client-side E2E (passthrough) 

def store_client_encrypted(ciphertext_b64: str, nonce_b64: str) -> tuple[str, str]:
    # When the client sends pre-encrypted content, we store it as-is. No server-side DEK is generated; returns the same values untouched.
    return ciphertext_b64, nonce_b64


# QR codes 

def generate_qr_code(url: str) -> str:
    """Returns a base64-encoded PNG QR code for the given URL."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()