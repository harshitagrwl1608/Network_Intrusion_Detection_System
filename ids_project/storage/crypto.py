"""
ids_project/storage/crypto.py
-----------------------------
Cryptographic helpers for credential encryption at rest.
Uses AES-128-CBC + HMAC-SHA256 via Fernet (cryptography library).

Security Invariants:
1. No hardcoded encryption-key or master-secret fallbacks in normal runtime.
2. Dedicated NETGUARD_ENCRYPTION_KEY required for credential encryption.
3. Independent from Flask session-signing key (NETGUARD_SECRET_KEY).
4. Fail-closed: encryption or decryption failures NEVER return plaintext or ciphertext.
5. Key material never logged, exposed in exceptions, or committed to repository.
"""

import os
import base64
import logging
from typing import Any, Dict, Set, Tuple
from cryptography.fernet import Fernet, InvalidToken
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

ENCRYPTION_PREFIX_V1 = "enc:v1:"
ENCRYPTION_PREFIX_V2 = "enc:v2:"
ENCRYPTION_PREFIX = ENCRYPTION_PREFIX_V1
ENCRYPTION_PREFIXES = (ENCRYPTION_PREFIX_V1, ENCRYPTION_PREFIX_V2)


class CryptoError(Exception):
    """Base exception for NetGuard cryptographic operations."""
    pass


class EncryptionConfigurationError(CryptoError):
    """Raised when encryption key is missing, malformed, or weak."""
    pass


class EncryptionError(CryptoError):
    """Raised when credential encryption fails."""
    pass


class DecryptionError(CryptoError):
    """Raised when credential decryption fails."""
    pass


def validate_encryption_key(key_str: str | None = None) -> bytes:
    """
    Validate and return a 32-byte urlsafe-base64 encoded Fernet key.
    Rejects missing, empty, or weak keys.
    Rejects keys identical to NETGUARD_SECRET_KEY or known historical insecure defaults.
    """
    if key_str is None:
        key_str = os.environ.get("NETGUARD_ENCRYPTION_KEY")

    if not key_str or not isinstance(key_str, str):
        raise EncryptionConfigurationError(
            "NETGUARD_ENCRYPTION_KEY is required for credential encryption at rest. "
            "Set a 32-byte base64-encoded key via environment variable."
        )

    key_clean = key_str.strip()
    if not key_clean:
        raise EncryptionConfigurationError("NETGUARD_ENCRYPTION_KEY cannot be empty.")

    # Reject known historical insecure default key
    if key_clean == "netguard-soc-default-master-key-seed-32b":
        raise EncryptionConfigurationError(
            "Insecure default key rejected. NETGUARD_ENCRYPTION_KEY must be a unique, dedicated key."
        )

    # Enforce separation from session-signing key
    secret_key = os.environ.get("NETGUARD_SECRET_KEY", "").strip()
    if secret_key and key_clean == secret_key:
        raise EncryptionConfigurationError(
            "NETGUARD_ENCRYPTION_KEY and NETGUARD_SECRET_KEY must be distinct and independent keys."
        )

    # Case 1: Standard 32-byte urlsafe-base64 Fernet key
    try:
        raw = base64.urlsafe_b64decode(key_clean.encode("utf-8"))
        if len(raw) == 32:
            return key_clean.encode("utf-8")
    except Exception:
        pass

    # Case 2: High-entropy passphrase (>= 32 characters)
    if len(key_clean) < 32:
        raise EncryptionConfigurationError(
            "NETGUARD_ENCRYPTION_KEY is invalid. It must either be a 32-byte urlsafe base64-encoded key "
            "(e.g., cryptography.fernet.Fernet.generate_key().decode()) "
            "or a high-entropy passphrase of at least 32 characters."
        )

    # For passphrase, derive a 32-byte key using PBKDF2 with an installation salt if configured
    salt = os.environ.get("NETGUARD_ENCRYPTION_SALT")
    if not salt:
        raise EncryptionConfigurationError(
            "Passphrase-based NETGUARD_ENCRYPTION_KEY requires NETGUARD_ENCRYPTION_SALT (>= 16 chars). "
            "Alternatively, use a 32-byte base64 Fernet key."
        )
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(key_clean.encode("utf-8")))


def get_fernet(key_override: str | None = None) -> Fernet:
    """Return Fernet cipher instance initialized with validated key."""
    key_bytes = validate_encryption_key(key_override)
    try:
        return Fernet(key_bytes)
    except Exception as exc:
        raise EncryptionConfigurationError(f"Failed to initialize Fernet cipher: {exc}") from exc


def encrypt_string(plaintext: str, key_override: str | None = None) -> str:
    """
    Encrypt a plaintext string, returning enc:v1:<token> or enc:v2:<salt>:<token>.
    Fails closed: NEVER returns plaintext on error.
    """
    if plaintext is None:
        return None
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    if not plaintext:
        return ""
    if any(plaintext.startswith(prefix) for prefix in ENCRYPTION_PREFIXES):
        return plaintext

    try:
        f = get_fernet(key_override)
        token = f.encrypt(plaintext.encode("utf-8")).decode("utf-8")
        return f"{ENCRYPTION_PREFIX_V1}{token}"
    except (CryptoError, Exception) as exc:
        logger.error(f"Credential encryption failed: {type(exc).__name__}")
        if isinstance(exc, CryptoError):
            raise
        raise EncryptionError(f"Encryption failed: {type(exc).__name__}") from exc


def decrypt_string(ciphertext: str, key_override: str | None = None) -> str:
    """
    Decrypt an encrypted credential string.
    Fails closed: NEVER returns ciphertext as a fallback credential.
    """
    if ciphertext is None:
        return None
    if not isinstance(ciphertext, str):
        return ciphertext
    if not ciphertext:
        return ""
    if not any(ciphertext.startswith(prefix) for prefix in ENCRYPTION_PREFIXES):
        return ciphertext

    try:
        if ciphertext.startswith(ENCRYPTION_PREFIX_V1):
            raw_token = ciphertext[len(ENCRYPTION_PREFIX_V1):]
            f = get_fernet(key_override)
            return f.decrypt(raw_token.encode("utf-8")).decode("utf-8")
        elif ciphertext.startswith(ENCRYPTION_PREFIX_V2):
            parts = ciphertext.split(":", 2)
            if len(parts) != 3:
                raise DecryptionError("Malformed enc:v2: ciphertext envelope")
            _, salt_b64, raw_token = parts
            salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
            passphrase = (key_override or os.environ.get("NETGUARD_ENCRYPTION_KEY") or "").strip()
            if not passphrase:
                raise EncryptionConfigurationError("NETGUARD_ENCRYPTION_KEY required for enc:v2: decryption")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
            )
            derived = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
            f = Fernet(derived)
            return f.decrypt(raw_token.encode("utf-8")).decode("utf-8")
        else:
            raise DecryptionError("Unsupported encryption envelope format")
    except InvalidToken as exc:
        logger.warning("Decryption failed: invalid token or encryption key mismatch")
        raise DecryptionError("Invalid encryption key or corrupted ciphertext") from exc
    except (CryptoError, Exception) as exc:
        logger.warning(f"Decryption failed: {type(exc).__name__}")
        if isinstance(exc, CryptoError):
            raise
        raise DecryptionError(f"Decryption failed: {type(exc).__name__}") from exc


def encrypt_dict_secrets(data: Dict[str, Any], existing: Dict[str, Any] | None = None, key_override: str | None = None) -> Dict[str, Any]:
    """
    Recursively encrypt sensitive keys in a dictionary.
    Preserves existing ciphertext on partial updates (empty string or masked '********').
    Fails closed: raises EncryptionError if encryption fails.
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
                    res[k] = encrypt_string(v_clean, key_override)
                else:
                    res[k] = ""
            elif v is None and existing and existing.get(k):
                res[k] = existing[k]
        elif isinstance(v, dict):
            sub_exist = existing.get(k) if (existing and isinstance(existing.get(k), dict)) else None
            res[k] = encrypt_dict_secrets(v, sub_exist, key_override)
    return res


def decrypt_dict_secrets(data: Dict[str, Any], key_override: str | None = None) -> Dict[str, Any]:
    """
    Recursively decrypt sensitive keys in a dictionary.
    Fails closed: raises DecryptionError if decryption fails on any sensitive field.
    """
    if not isinstance(data, dict):
        return data

    res = dict(data)
    for k, v in list(res.items()):
        if k in SENSITIVE_KEYS and isinstance(v, str):
            if any(v.startswith(prefix) for prefix in ENCRYPTION_PREFIXES):
                res[k] = decrypt_string(v, key_override)
        elif isinstance(v, dict):
            res[k] = decrypt_dict_secrets(v, key_override)
    return res


def migrate_legacy_credentials(conn, legacy_key: str | None = None) -> Dict[str, Any]:
    """
    Controlled migration utility for legacy settings.
    - If records are encrypted with legacy fallback key, decrypts with explicitly provided legacy_key.
    - Re-encrypts with active NETGUARD_ENCRYPTION_KEY.
    - If legacy_key is not supplied, reports unmigrated records requiring manual rotation.
    - Transactional: rolls back if any failure occurs.
    """
    import json
    from storage.db import _sqlite_lock, adapt_sql

    result = {
        "migrated": [],
        "unmigrated": [],
        "errors": [],
    }

    legacy_fernet = None
    if legacy_key:
        old_salt = b"netguard_credential_encryption_v1_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=old_salt,
            iterations=100_000,
        )
        derived = base64.urlsafe_b64encode(kdf.derive(legacy_key.encode("utf-8")))
        legacy_fernet = Fernet(derived)

    # Active key validation
    active_fernet = get_fernet()

    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(adapt_sql("SELECT setting_key, value_json FROM system_settings"))
        rows = cur.fetchall()
        cur.close()

    updates = []
    for r in rows:
        key = r[0] if isinstance(r, (tuple, list)) else r["setting_key"]
        v_json = r[1] if isinstance(r, (tuple, list)) else r["value_json"]
        if not v_json:
            continue
        try:
            val = json.loads(v_json)
        except Exception:
            continue

        needs_update = False
        if isinstance(val, dict):
            decrypted_dict = dict(val)
            for sk, sv in list(val.items()):
                if sk in SENSITIVE_KEYS and isinstance(sv, str) and sv.startswith(ENCRYPTION_PREFIX_V1):
                    # Try decrypting with active key first
                    try:
                        active_fernet.decrypt(sv[len(ENCRYPTION_PREFIX_V1):].encode("utf-8"))
                        # Already on active key
                        continue
                    except InvalidToken:
                        pass

                    # Needs migration
                    if legacy_fernet:
                        try:
                            recovered = legacy_fernet.decrypt(sv[len(ENCRYPTION_PREFIX_V1):].encode("utf-8")).decode("utf-8")
                            re_encrypted = active_fernet.encrypt(recovered.encode("utf-8")).decode("utf-8")
                            decrypted_dict[sk] = f"{ENCRYPTION_PREFIX_V1}{re_encrypted}"
                            needs_update = True
                        except Exception as exc:
                            result["errors"].append(f"{key}.{sk}: legacy decryption failed ({exc})")
                            result["unmigrated"].append(f"{key}.{sk}")
                    else:
                        result["unmigrated"].append(f"{key}.{sk}")

            if needs_update:
                updates.append((key, json.dumps(decrypted_dict)))
                result["migrated"].append(key)

    # Apply updates transactionally
    if updates:
        try:
            with _sqlite_lock:
                cur = conn.cursor()
                for k, v in updates:
                    cur.execute(
                        adapt_sql("UPDATE system_settings SET value_json = ? WHERE setting_key = ?"),
                        (v, k)
                    )
                conn.commit()
                cur.close()
        except Exception as exc:
            conn.rollback()
            raise CryptoError(f"Migration transaction failed: {exc}") from exc

    return result
