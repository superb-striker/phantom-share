from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag

from app.services.file_crypto import CHUNK_SIZE, decrypt_file, encrypt_file


def test_file_encryption_round_trip_across_chunks(tmp_path):
    source = tmp_path / "source"
    encrypted = tmp_path / "encrypted"
    restored = tmp_path / "restored"
    payload = b"a" * (CHUNK_SIZE + 17) + b"tail"
    source.write_bytes(payload)
    key = bytes(range(32))
    secret_id = uuid4()

    size, digest = encrypt_file(source, encrypted, key, secret_id, 3)
    decrypt_file(encrypted, restored, key, secret_id, 3)

    assert size == len(payload)
    assert len(digest) == 64
    assert restored.read_bytes() == payload
    assert payload not in encrypted.read_bytes()


def test_file_encryption_detects_tampering(tmp_path):
    source = tmp_path / "source"
    encrypted = tmp_path / "encrypted"
    restored = tmp_path / "restored"
    source.write_bytes(b"confidential")
    key = bytes(range(32))
    secret_id = uuid4()
    encrypt_file(source, encrypted, key, secret_id, 1)
    damaged = bytearray(encrypted.read_bytes())
    damaged[-1] ^= 1
    encrypted.write_bytes(damaged)

    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, restored, key, secret_id, 1)


def test_file_ciphertext_is_bound_to_version(tmp_path):
    source = tmp_path / "source"
    encrypted = tmp_path / "encrypted"
    source.write_bytes(b"confidential")
    key = bytes(range(32))
    secret_id = uuid4()
    encrypt_file(source, encrypted, key, secret_id, 1)

    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, tmp_path / "restored", key, secret_id, 2)
