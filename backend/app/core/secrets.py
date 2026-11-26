"""Secret protection helpers. Raw values must never be logged or returned."""

import hashlib
import hmac
import os

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class SecretConfigurationError(RuntimeError):
    pass


def _cipher() -> Fernet:
    configured_key = get_settings().INTEGRATION_ENCRYPTION_KEY
    if configured_key is None:
        raise SecretConfigurationError("Integration secret encryption is not configured")
    try:
        return Fernet(configured_key.get_secret_value().encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise SecretConfigurationError("Integration secret encryption is not configured correctly") from exc


def encryption_is_configured() -> bool:
    try:
        _cipher()
        return True
    except SecretConfigurationError:
        return False


def encrypt_secret(raw_secret: str) -> bytes:
    return _cipher().encrypt(raw_secret.encode("utf-8"))


def decrypt_secret(encrypted_secret: bytes) -> str:
    try:
        return _cipher().decrypt(encrypted_secret).decode("utf-8")
    except InvalidToken as exc:
        raise SecretConfigurationError("Stored integration secret cannot be decrypted") from exc


def hash_api_key(raw_key: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    actual_salt = salt or os.urandom(16)
    digest = hashlib.scrypt(
        raw_key.encode("utf-8"), salt=actual_salt, n=2**14, r=8, p=1, dklen=32
    )
    return digest, actual_salt


def verify_api_key(raw_key: str, expected_hash: bytes, salt: bytes) -> bool:
    candidate_hash, _ = hash_api_key(raw_key, salt)
    return hmac.compare_digest(candidate_hash, expected_hash)


def masked_hint(raw_secret: str) -> str:
    prefix = raw_secret[:4]
    suffix = raw_secret[-4:]
    return f"{prefix}••••{suffix}"
