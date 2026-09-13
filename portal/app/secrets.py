"""Small, authenticated encryption wrapper for administrative secrets."""
import os
from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"

def _fernet() -> Fernet:
    key = os.getenv("CATS_CONFIG_ENCRYPTION_KEY", "").strip()
    if not key:
        raise ValueError("CATS_CONFIG_ENCRYPTION_KEY is required to store encrypted configuration secrets")
    try:
        return Fernet(key.encode())
    except Exception as exc:
        raise ValueError("CATS_CONFIG_ENCRYPTION_KEY is not a valid Fernet key") from exc

def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    return PREFIX + _fernet().encrypt(value.encode()).decode()

def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    if not value.startswith(PREFIX):
        raise ValueError("Stored secret is not encrypted")
    try:
        return _fernet().decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Stored secret could not be decrypted") from exc

def secret_configured(value: str) -> bool:
    return bool(value and value.startswith(PREFIX))
