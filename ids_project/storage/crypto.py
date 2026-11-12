"""
ids_project/storage/crypto.py
-----------------------------
Cryptographic helpers for credential encryption at rest.
Uses AES-128-CBC + HMAC-SHA256 via Fernet (cryptography library).
Derives 32-byte key from NETGUARD_ENCRYPTION_KEY or NETGUARD_SECRET_KEY using PBKDF2-HMAC-SHA256.
"""

import os
import base64
import json
import logging
from typing import Any, Dict, Set
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

SENSITIVE_KEYS: Set[str] = {
    "password",
    "auth_token",
    "bot_token",
    "secret",
    "secret_key",
    "smtp_password",
    "api_key",
}

ENCRYPTION_PREFIX = "enc:v1:"
_SALT = b"netguard_credential_encryption_v1_salt"


def get_fernet() -> Fernet:
    """Return Fernet cipher initialized from env or deterministic PBKDF2 derivation."""
    key_env = os.environ.get("NETGUARD_ENCRYPTION_KEY")
    if key_env:
        try:
            return Fernet(key_env.strip().encode("utf-8"))
        except Exception:
            pass

    secret = os.environ.get("NETGUARD_SECRET_KEY", "netguard-soc-default-master-key-seed-32b")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=100_000,
    )
    derived = base64.urlsafe_b64encode(kdf.derive(secret.encode("utf-8")))
    return Fernet(derived)


def encrypt_string(plaintext: str) -> str:
    """Encrypt a plaintext string, returning enc:v1:<ciphertext>."""
    if not plaintext or not isinstance(plaintext, str):
        return plaintext
    if plaintext.startswith(ENCRYPTION_PREFIX):
        return plaintext
    try:
        f = get_fernet()
        token = f.encrypt(plaintext.encode("utf-8")).decode("utf-8")
        return f"{ENCRYPTION_PREFIX}{token}"
    except Exception as exc:
        logger.error(f"Failed to encrypt secret: {exc}")
        return plaintext


def decrypt_string(ciphertext: str) -> str:
    """Decrypt an enc:v1:<ciphertext> string. Returns original if not encrypted or on error."""
    if not ciphertext or not isinstance(ciphertext, str):
        return ciphertext
    if not ciphertext.startswith(ENCRYPTION_PREFIX):
        return ciphertext
    raw_token = ciphertext[len(ENCRYPTION_PREFIX):]
    try:
        f = get_fernet()
        return f.decrypt(raw_token.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        logger.warning(f"Failed to decrypt credential (key mismatch?): {exc}")
        return ciphertext


def encrypt_dict_secrets(data: Dict[str, Any], existing: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """
    Recursively encrypt sensitive keys in a dictionary.
    If a sensitive key in `data` is empty, None, or '********', and `existing` has a value,
    preserves the existing secret rather than destroying it.
    """
    if not isinstance(data, dict):
        return data

    res = dict(data)
    for k, v in list(res.items()):
        if k in SENSITIVE_KEYS:
            if isinstance(v, str):
                v_clean = v.strip()
                if v_clean in ("", "********") and existing and existing.get(k):
                    # Preserve existing encrypted secret
                    res[k] = existing[k]
                elif v_clean and v_clean != "********":
                    res[k] = encrypt_string(v_clean)
                else:
                    res[k] = ""
            elif v is None and existing and existing.get(k):
                res[k] = existing[k]
        elif isinstance(v, dict):
            sub_exist = existing.get(k) if (existing and isinstance(existing.get(k), dict)) else None
            res[k] = encrypt_dict_secrets(v, sub_exist)
    return res


def decrypt_dict_secrets(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively decrypt sensitive keys in a dictionary."""
    if not isinstance(data, dict):
        return data

    res = dict(data)
    for k, v in list(res.items()):
        if k in SENSITIVE_KEYS and isinstance(v, str):
            res[k] = decrypt_string(v)
        elif isinstance(v, dict):
            res[k] = decrypt_dict_secrets(v)
    return res

