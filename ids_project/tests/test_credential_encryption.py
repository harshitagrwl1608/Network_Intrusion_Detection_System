"""
ids_project/tests/test_credential_encryption.py
-----------------------------------------------
Tests verifying:
1. AES-128-CBC + HMAC-SHA256 (Fernet) credential encryption at rest.
2. Transparent decryption on retrieval.
3. Raw database inspection confirming no plaintext credentials exist on disk.
4. Partial form updates (blank or masked password) do not destroy existing credentials.
5. NotificationOutboxManager round-trip persistence and reload.
"""

import os
import sys
import json
import sqlite3
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from storage.crypto import (
    encrypt_string, decrypt_string, encrypt_dict_secrets,
    decrypt_dict_secrets, ENCRYPTION_PREFIX
)
from storage.forensics_db import (
    init_forensics_db, save_system_setting, get_system_setting
)
from notifications.outbox import NotificationOutboxManager


@pytest.fixture
def test_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_forensics_db(conn)
    yield conn
    conn.close()


def test_crypto_primitive_roundtrip():
    """Verify encrypt_string and decrypt_string functionality."""
    plain = "SuperSecret_P@ssw0rd!_2026"
    encrypted = encrypt_string(plain)
    assert encrypted.startswith(ENCRYPTION_PREFIX)
    assert encrypted != plain
    assert plain not in encrypted

    decrypted = decrypt_string(encrypted)
    assert decrypted == plain


def test_crypto_dict_encryption():
    """Verify recursive encryption of sensitive keys in dictionaries."""
    data = {
        "host": "smtp.domain.com",
        "port": 587,
        "user": "analyst@domain.com",
        "password": "CleartextPassword123",
        "nested": {
            "auth_token": "token_abc_xyz_789",
            "non_secret": "hello",
        }
    }
    enc_dict = encrypt_dict_secrets(data)
    assert enc_dict["password"].startswith(ENCRYPTION_PREFIX)
    assert "CleartextPassword123" not in enc_dict["password"]
    assert enc_dict["nested"]["auth_token"].startswith(ENCRYPTION_PREFIX)
    assert "token_abc_xyz_789" not in enc_dict["nested"]["auth_token"]
    assert enc_dict["host"] == "smtp.domain.com"
    assert enc_dict["nested"]["non_secret"] == "hello"

    dec_dict = decrypt_dict_secrets(enc_dict)
    assert dec_dict["password"] == "CleartextPassword123"
    assert dec_dict["nested"]["auth_token"] == "token_abc_xyz_789"
    assert dec_dict["host"] == "smtp.domain.com"


def test_database_raw_inspection_no_plaintext(test_db):
    """Verify raw database records never store plaintext credentials."""
    setting = {
        "host": "smtp.gmail.com",
        "user": "soc@gmail.com",
        "password": "MySuperSecretPassword",
        "bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
    }
    save_system_setting(test_db, "notification_email", setting)

    # Inspect raw JSON directly from SQLite table
    cur = test_db.cursor()
    cur.execute("SELECT value_json FROM system_settings WHERE setting_key = 'notification_email'")
    row = cur.fetchone()
    cur.close()

    raw_json = row["value_json"]
    assert "MySuperSecretPassword" not in raw_json
    assert "123456:ABC-DEF" not in raw_json
    assert ENCRYPTION_PREFIX in raw_json

    # Retrieve via API helper: must be decrypted
    retrieved = get_system_setting(test_db, "notification_email")
    assert retrieved["password"] == "MySuperSecretPassword"
    assert retrieved["bot_token"] == "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"


def test_partial_update_preserves_existing_secret(test_db):
    """Verify submitting a form with blank password does not erase existing stored credential."""
    initial = {
        "host": "smtp.initial.com",
        "user": "admin@initial.com",
        "password": "ExistingSavedPassword999",
    }
    save_system_setting(test_db, "notification_email", initial)

    # Operator changes host, leaving password field blank
    update = {
        "host": "smtp.updated.com",
        "user": "admin@updated.com",
        "password": "",  # Blank resubmission
    }
    save_system_setting(test_db, "notification_email", update)

    retrieved = get_system_setting(test_db, "notification_email")
    assert retrieved["host"] == "smtp.updated.com"
    assert retrieved["user"] == "admin@updated.com"
    # Secret must be preserved!
    assert retrieved["password"] == "ExistingSavedPassword999"

    # Also verify masked password resubmission ("********") preserves secret
    update_masked = {
        "host": "smtp.updated.com",
        "user": "admin@updated.com",
        "password": "********",
    }
    save_system_setting(test_db, "notification_email", update_masked)
    retrieved2 = get_system_setting(test_db, "notification_email")
    assert retrieved2["password"] == "ExistingSavedPassword999"


def test_notification_outbox_manager_lifecycle(test_db):
    """Verify NotificationOutboxManager configures, saves encrypted, and reloads credentials."""
    mgr = NotificationOutboxManager()
    mgr.set_connection(test_db)

    # Configure Telegram with bot token
    ok, msg = mgr.configure_provider("telegram", {
        "bot_token": "telegram_secret_token_12345",
        "chat_id": "-100123456789",
    }, persist=True)
    assert ok is True

    # Check raw DB
    cur = test_db.cursor()
    cur.execute("SELECT value_json FROM system_settings WHERE setting_key = 'notification_telegram'")
    raw_json = cur.fetchone()["value_json"]
    cur.close()
    assert "telegram_secret_token_12345" not in raw_json
    assert ENCRYPTION_PREFIX in raw_json

    # Create fresh manager instance simulating process restart
    mgr2 = NotificationOutboxManager()
    mgr2.set_connection(test_db)
    mgr2.reload_providers_from_db()

    provider = mgr2.get_provider("telegram")
    assert provider is not None
    assert getattr(provider, "bot_token", None) == "telegram_secret_token_12345"
    assert getattr(provider, "chat_id", None) == "-100123456789"

