import base64
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import app.helper as helper


class TestDEKLifecycle:
    def test_generate_dek_is_32_bytes(self):
        assert len(helper.generate_dek()) == 32

    def test_generate_dek_is_unique_each_call(self):
        deks = {helper.generate_dek() for _ in range(50)}
        assert len(deks) == 50

    def test_wrap_unwrap_round_trip(self):
        dek = helper.generate_dek()
        wrapped_b64, nonce_b64 = helper.wrap_dek(dek)
        assert helper.unwrap_dek(wrapped_b64, nonce_b64) == dek

    def test_unwrap_with_tampered_ciphertext_fails(self):
        dek = helper.generate_dek()
        wrapped_b64, nonce_b64 = helper.wrap_dek(dek)
        raw = bytearray(base64.b64decode(wrapped_b64))
        raw[0] ^= 0xFF
        tampered_b64 = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError, match="DEK unwrap failed"):
            helper.unwrap_dek(tampered_b64, nonce_b64)

    def test_unwrap_with_wrong_nonce_fails(self):
        dek = helper.generate_dek()
        wrapped_b64, _ = helper.wrap_dek(dek)
        wrong_nonce_b64 = base64.b64encode(os.urandom(12)).decode()
        with pytest.raises(ValueError):
            helper.unwrap_dek(wrapped_b64, wrong_nonce_b64)


class TestContentEncryption:
    def test_encrypt_decrypt_round_trip(self):
        dek = helper.generate_dek()
        ct_b64, nonce_b64 = helper.encrypt_content("top secret text", dek)
        assert helper.decrypt_content(ct_b64, nonce_b64, dek) == "top secret text"

    def test_decrypt_with_wrong_dek_fails(self):
        dek = helper.generate_dek()
        other_dek = helper.generate_dek()
        ct_b64, nonce_b64 = helper.encrypt_content("hello", dek)
        with pytest.raises(ValueError, match="Content decryption failed"):
            helper.decrypt_content(ct_b64, nonce_b64, other_dek)

    def test_decrypt_with_tampered_ciphertext_fails(self):
        dek = helper.generate_dek()
        ct_b64, nonce_b64 = helper.encrypt_content("hello", dek)
        raw = bytearray(base64.b64decode(ct_b64))
        raw[-1] ^= 0xFF
        tampered_b64 = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError):
            helper.decrypt_content(tampered_b64, nonce_b64, dek)

    def test_empty_string_round_trip(self):
        dek = helper.generate_dek()
        ct_b64, nonce_b64 = helper.encrypt_content("", dek)
        assert helper.decrypt_content(ct_b64, nonce_b64, dek) == ""

    def test_unicode_content_round_trip(self):
        dek = helper.generate_dek()
        text = "pässwörd \U0001F512 \u5bc6\u7801"
        ct_b64, nonce_b64 = helper.encrypt_content(text, dek)
        assert helper.decrypt_content(ct_b64, nonce_b64, dek) == text

    def test_ciphertext_differs_each_call_due_to_random_nonce(self):
        dek = helper.generate_dek()
        c1, n1 = helper.encrypt_content("same text", dek)
        c2, n2 = helper.encrypt_content("same text", dek)
        assert n1 != n2
        assert c1 != c2


class TestKEKLoading:
    def test_load_kek_from_valid_base64(self, monkeypatch):
        key = ChaCha20Poly1305.generate_key()
        key_b64 = base64.b64encode(key).decode()
        monkeypatch.setattr(helper.settings, "SECRET_ENCRYPTION_KEY", key_b64)
        assert helper._load_kek() == key

    def test_load_kek_wrong_length_raises(self, monkeypatch):
        bad_key_b64 = base64.b64encode(os.urandom(16)).decode()
        monkeypatch.setattr(helper.settings, "SECRET_ENCRYPTION_KEY", bad_key_b64)
        with pytest.raises(ValueError, match="must decode to"):
            helper._load_kek()

    def test_load_kek_generates_ephemeral_when_unset(self, monkeypatch, caplog):
        monkeypatch.setattr(helper.settings, "SECRET_ENCRYPTION_KEY", "")
        with caplog.at_level("WARNING"):
            key = helper._load_kek()
        assert len(key) == 32
        assert "ephemeral kek" in caplog.text.lower()


class TestClientEncryptedValidation:
    def test_valid_input_passes(self):
        nonce_b64 = base64.b64encode(os.urandom(12)).decode()
        ct_b64 = base64.b64encode(b"anything").decode()
        helper.validate_client_encrypted(ct_b64, nonce_b64)

    def test_wrong_nonce_length_rejected(self):
        nonce_b64 = base64.b64encode(os.urandom(16)).decode()
        ct_b64 = base64.b64encode(b"anything").decode()
        with pytest.raises(ValueError, match="12 bytes"):
            helper.validate_client_encrypted(ct_b64, nonce_b64)

    def test_malformed_nonce_base64_rejected(self):
        with pytest.raises(ValueError, match="nonce_b64"):
            helper.validate_client_encrypted("YQ==", "not-valid-base64!!!")

    def test_malformed_ciphertext_base64_rejected(self):
        nonce_b64 = base64.b64encode(os.urandom(12)).decode()
        with pytest.raises(ValueError, match="ciphertext_b64"):
            helper.validate_client_encrypted("not-valid-base64!!!", nonce_b64)


class TestQRCode:
    def test_generates_valid_base64_png(self):
        result = helper.generate_qr_code("https://example.com/s/abc123")
        raw = base64.b64decode(result)
        assert raw.startswith(b"\x89PNG\r\n\x1a\n")
