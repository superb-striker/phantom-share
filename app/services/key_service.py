"""
key_service.py – Key Management System (KMS).
Responsibilities:
  - Generate and wrap a fresh DEK for each new secret.
  - Store the wrapped DEK in secret_keys table.
  - Retrieve and unwrap a DEK for decryption.
  - Rotate a DEK: re-encrypt the secret content under a new DEK.
"""

from datetime import datetime, timezone
from psycopg_pool import AsyncConnectionPool

from app.helper import (
    decrypt_content,
    encrypt_content,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)

async def create_key_for_secret(
    conn, secret_id: str
) -> tuple[bytes, str, str]:
    # Generate a DEK, wrap it, persist to secret_keys. Returns (dek_bytes, wrapped_dek_b64, dek_nonce_b64).
    dek = generate_dek()
    wrapped_dek, dek_nonce = wrap_dek(dek)
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO secret_keys (secret_id, wrapped_dek, dek_nonce, version)
            VALUES (%s, %s, %s, 1)
            """,
            (secret_id, wrapped_dek, dek_nonce),
        )
    return dek, wrapped_dek, dek_nonce

async def get_dek_for_secret(conn, secret_id: str) -> bytes:
    # Load the latest (highest version) wrapped DEK and unwrap it. Returns plaintext DEK bytes.
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT wrapped_dek, dek_nonce
            FROM secret_keys
            WHERE secret_id = %s
            ORDER BY version DESC
            LIMIT 1
            """,
            (secret_id,),
        )
        row = await cur.fetchone()
    if not row:
        raise ValueError(f"No encryption key found for secret {secret_id}")
    return unwrap_dek(row[0], row[1])

async def rotate_key(pool: AsyncConnectionPool, secret_id: str) -> int:
    """
    Re-encrypt the secret's content under a brand new DEK.
    Returns the new key version number.
    Steps:
      1. Fetch old DEK + ciphertext.
      2. Decrypt with old DEK.
      3. Generate new DEK, re-encrypt.
      4. Persist new wrapped DEK and updated ciphertext atomically.
    """
    async with pool.connection() as conn:
        async with conn.transaction():
            # Fetch current ciphertext + nonce
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT content, nonce FROM secrets WHERE id = %s FOR UPDATE",
                    (secret_id,),
                )
                secret_row = await cur.fetchone()
            if not secret_row:
                raise ValueError(f"Secret {secret_id} not found")
            old_ciphertext, old_nonce = secret_row
            # Unwrap old DEK
            old_dek = await get_dek_for_secret(conn, secret_id)
            # Decrypt content
            plaintext = decrypt_content(old_ciphertext, old_nonce, old_dek)
            # Generate new DEK and re-encrypt
            new_dek = generate_dek()
            new_ciphertext, new_nonce = encrypt_content(plaintext, new_dek)
            new_wrapped, new_dek_nonce = wrap_dek(new_dek)
            async with conn.cursor() as cur:
                # Get next version
                await cur.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM secret_keys WHERE secret_id = %s",
                    (secret_id,),
                )
                current_version = (await cur.fetchone())[0]
                new_version = current_version + 1
                # Insert new key record
                await cur.execute(
                    """
                    INSERT INTO secret_keys
                        (secret_id, wrapped_dek, dek_nonce, version, rotated_at)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        secret_id,
                        new_wrapped,
                        new_dek_nonce,
                        new_version,
                        datetime.now(timezone.utc),
                    ),
                )
                # Update secret content
                await cur.execute(
                    "UPDATE secrets SET content = %s, nonce = %s WHERE id = %s",
                    (new_ciphertext, new_nonce, secret_id),
                )
    return new_version