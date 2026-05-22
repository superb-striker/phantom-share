"""
key_service.py – Key Management System (KMS).
Responsibilities:
  - Generate and wrap a fresh DEK for each new secret.
  - Store the wrapped DEK in secret_keys table.
  - Retrieve and unwrap a DEK for decryption.
  - Rotate a DEK: re-encrypt the secret content under a new DEK.
"""
from psycopg.rows import dict_row
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
    '''Generate a DEK, wrap it, persist to secret_keys. 
    
    Returns (dek_bytes, wrapped_dek_b64, dek_nonce_b64).
    
    Warning:
        The returned dek_bytes is plaintext key material.
        Use it immediately and do not persist it.
    '''
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
    '''Load the latest wrapped DEK for a secret and unwrap it.
 
    Returns:
        Plaintext DEK bytes.
 
    Raises:
        ValueError: if no key record exists for the secret.
    '''
    async with conn.cursor(row_factory=dict_row) as cur:
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
    return unwrap_dek(row["wrapped_dek"], row["dek_nonce"])

async def rotate_key(pool: AsyncConnectionPool, secret_id: str) -> int:
    '''
    Re-encrypt a secret's content under a brand-new DEK.
 
    Steps:
      1. Lock and fetch the current ciphertext.
      2. Unwrap the old DEK (reusing the same transactional connection).
      3. Decrypt content; hold plaintext as a mutable bytearray.
      4. Generate a new DEK and re-encrypt.
      5. Persist the new wrapped DEK and updated ciphertext atomically.
         Version number is computed in SQL to avoid a race between concurrent
         rotation attempts reading the same MAX(version).
 
    Returns:
        The new key version number.
 
    Raises:
        ValueError: if the secret does not exist.
    '''
    async with pool.connection() as conn:
        async with conn.transaction():
            # Step 1 : lock the secrets row for the duration of the transaction
            # to prevent concurrent rotations from interleaving.
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    "SELECT content, nonce FROM secrets WHERE id = %s FOR UPDATE",
                    (secret_id,),
                )
                secret_row = await cur.fetchone()
            if not secret_row:
                raise ValueError(f"Secret {secret_id} not found")
            old_ciphertext = secret_row["content"]
            old_nonce = secret_row["nonce"]
            # Step 2 : reuse the same transactional connection so get_dek_for_secret
            # sees the locked state and participates in the same transaction.
            old_dek = await get_dek_for_secret(conn, secret_id)
            # Step 3 : decrypt; use bytearray so we can zero it after use.
            plaintext_bytes = bytearray(
                decrypt_content(old_ciphertext, old_nonce, old_dek).encode()
            )
            try:
                # Step 4 : generate a new DEK and re-encrypt.
                new_dek = generate_dek()
                new_ciphertext, new_nonce = encrypt_content(
                    plaintext_bytes.decode(), new_dek
                )
                new_wrapped, new_dek_nonce = wrap_dek(new_dek)
            finally:
                # Zero out plaintext regardless of success or failure.
                for i in range(len(plaintext_bytes)):
                    plaintext_bytes[i] = 0
            # Step 5 : insert new key record with an atomically computed version,
            # then update the secret ciphertext; both happen inside the transaction.
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO secret_keys
                        (secret_id, wrapped_dek, dek_nonce, version, rotated_at)
                    SELECT %s, %s, %s, COALESCE(MAX(version), 0) + 1, %s
                    FROM secret_keys
                    WHERE secret_id = %s
                    RETURNING version
                    """,
                    (
                        secret_id,
                        new_wrapped,
                        new_dek_nonce,
                        datetime.now(timezone.utc),
                        secret_id,
                    ),
                )
                row = await cur.fetchone()
                new_version = row[0] if row else 0
                await cur.execute(
                    "UPDATE secrets SET content = %s, nonce = %s WHERE id = %s",
                    (new_ciphertext, new_nonce, secret_id),
                )
    return new_version