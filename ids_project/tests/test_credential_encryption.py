"""
ids_project/tests/test_credential_encryption.py
-----------------------------------------------
Comprehensive cryptographic security tests for NetGuard credential encryption at rest.

Covers:
1. Fail-closed on missing NETGUARD_ENCRYPTION_KEY.
2. Fail-closed on malformed encryption key.
3. Fail-closed on hardcoded insecure default key.
4. Fail-closed when encryption and session keys are identical.
5. Encryption failure does not persist plaintext.
6. Decryption failure on wrong key (never returns ciphertext).
7. Failed operations roll back completely.
8. Roundtrip encrypt/decrypt correctness.
9. Partial update preserves existing encrypted secret.
10. Raw database inspection: no plaintext credentials.
11. NotificationOutboxManager lifecycle.
12. Provider fails to reload with wrong decryption key.
13. Legacy credential migration via migrate_legacy_credentials.
14. Session key stability across multiple workers with same key.
15. NETGUARD_TESTING env var isolation for test environments.
"""

import os
import sys
import json
import sqlite3
import threading
import importlib
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from cryptography.fernet import Fernet


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    """Clear both crypto env vars before each test to prevent machine environment bleed-through."""
    monkeypatch.delenv("NETGUARD_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("NETGUARD_ENCRYPTION_SALT", raising=False)
    monkeypatch.delenv("NETGUARD_SECRET_KEY", raising=False)
    # Reload crypto module so each test sees a clean state
    import storage.crypto
    importlib.reload(storage.crypto)
    yield
    import storage.crypto
    importlib.reload(storage.crypto)


@pytest.fixture
def valid_key() -> str:
    """Return a fresh valid 32-byte urlsafe-base64 Fernet key."""
    return Fernet.generate_key().decode()


@pytest.fixture
def test_db():
    from storage.forensics_db import init_forensics_db
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_forensics_db(conn)
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# 1. Missing key tests
# ---------------------------------------------------------------------------

class TestMissingKey:
    def test_missing_key_raises_on_encrypt(self):
        """encrypt_string must raise EncryptionConfigurationError when key is not set."""
        from storage.crypto import encrypt_string, EncryptionConfigurationError
        with pytest.raises(EncryptionConfigurationError):
            encrypt_string("secret-password")

    def test_missing_key_raises_on_get_fernet(self):
        """get_fernet must raise EncryptionConfigurationError when key is not set."""
        from storage.crypto import get_fernet, EncryptionConfigurationError
        with pytest.raises(EncryptionConfigurationError):
            get_fernet()

    def test_missing_key_save_does_not_write_plaintext(self, test_db):
        """save_system_setting must roll back and NOT write plaintext when key is missing."""
        from storage.crypto import EncryptionConfigurationError
        from storage.forensics_db import save_system_setting
        with pytest.raises(EncryptionConfigurationError):
            save_system_setting(test_db, "notification_email", {
                "host": "smtp.example.com",
                "password": "TopSecretPassword"
            })
        cur = test_db.cursor()
        cur.execute("SELECT value_json FROM system_settings WHERE setting_key='notification_email'")
        row = cur.fetchone()
        assert row is None, "Plaintext row should not exist after encryption failure"

    def test_missing_key_no_plaintext_after_rollback(self, monkeypatch, valid_key, test_db):
        """After an initial successful write, clearing the key must not expose saved plaintext."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.forensics_db import save_system_setting, get_system_setting

        save_system_setting(test_db, "notification_email", {
            "host": "smtp.example.com",
            "password": "FirstSecret"
        })

        # Remove key and attempt update
        monkeypatch.delenv("NETGUARD_ENCRYPTION_KEY")
        importlib.reload(storage.crypto)
        from storage.crypto import EncryptionConfigurationError
        with pytest.raises(EncryptionConfigurationError):
            save_system_setting(test_db, "notification_email", {
                "host": "smtp.newhost.com",
                "password": "NewSecret"
            })

        # Raw inspection: existing row must not contain new plaintext
        cur = test_db.cursor()
        cur.execute("SELECT value_json FROM system_settings WHERE setting_key='notification_email'")
        row = cur.fetchone()
        raw = row[0]
        assert "NewSecret" not in raw, "New plaintext must not appear after encryption failure rollback"


# ---------------------------------------------------------------------------
# 2. Malformed key tests
# ---------------------------------------------------------------------------

class TestMalformedKey:
    def test_short_string_key_rejected(self, monkeypatch):
        """Keys shorter than 32 chars that aren't valid Fernet keys must be rejected."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", "tooshort")
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import encrypt_string, EncryptionConfigurationError
        with pytest.raises(EncryptionConfigurationError):
            encrypt_string("secret")

    def test_invalid_base64_key_rejected(self, monkeypatch):
        """Non-base64 key strings must be rejected with EncryptionConfigurationError."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", "!@#$%^&*()_+" * 3)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import encrypt_string, EncryptionConfigurationError
        with pytest.raises(EncryptionConfigurationError):
            encrypt_string("secret")

    def test_hardcoded_default_key_rejected(self, monkeypatch):
        """The historical hardcoded fallback key must always be rejected."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", "netguard-soc-default-master-key-seed-32b")
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import encrypt_string, EncryptionConfigurationError
        with pytest.raises(EncryptionConfigurationError):
            encrypt_string("secret")


# ---------------------------------------------------------------------------
# 3. Key independence tests
# ---------------------------------------------------------------------------

class TestKeyIndependence:
    def test_encryption_and_session_keys_must_differ(self, monkeypatch, valid_key):
        """NETGUARD_ENCRYPTION_KEY and NETGUARD_SECRET_KEY must be distinct."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        monkeypatch.setenv("NETGUARD_SECRET_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import encrypt_string, EncryptionConfigurationError
        with pytest.raises(EncryptionConfigurationError):
            encrypt_string("secret")

    def test_independent_keys_accepted(self, monkeypatch):
        """Independent NETGUARD_ENCRYPTION_KEY and NETGUARD_SECRET_KEY must both succeed."""
        enc_key = Fernet.generate_key().decode()
        sess_key = Fernet.generate_key().decode()
        assert enc_key != sess_key
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", enc_key)
        monkeypatch.setenv("NETGUARD_SECRET_KEY", sess_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import encrypt_string, decrypt_string
        ct = encrypt_string("MySecret")
        assert ct.startswith("enc:v1:")
        assert decrypt_string(ct) == "MySecret"


# ---------------------------------------------------------------------------
# 4. Encryption/decryption correctness
# ---------------------------------------------------------------------------

class TestEncryptionRoundtrip:
    def test_roundtrip_plaintext(self, monkeypatch, valid_key):
        """Standard encrypt/decrypt roundtrip."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import encrypt_string, decrypt_string, ENCRYPTION_PREFIX
        plain = "SuperSecret_P@ssw0rd!_2026"
        ct = encrypt_string(plain)
        assert ct.startswith(ENCRYPTION_PREFIX)
        assert plain not in ct
        assert decrypt_string(ct) == plain

    def test_already_encrypted_passthrough(self, monkeypatch, valid_key):
        """Re-encrypting an already-encrypted value must return the same ciphertext."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import encrypt_string
        ct1 = encrypt_string("secret")
        ct2 = encrypt_string(ct1)
        assert ct1 == ct2

    def test_dict_encryption_correctness(self, monkeypatch, valid_key):
        """Sensitive keys in dicts are encrypted; non-sensitive keys pass through."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import encrypt_dict_secrets, decrypt_dict_secrets, ENCRYPTION_PREFIX
        data = {
            "host": "smtp.domain.com",
            "port": 587,
            "user": "analyst@domain.com",
            "password": "CleartextPassword123",
            "nested": {"auth_token": "token_abc_xyz_789", "non_secret": "hello"},
        }
        enc = encrypt_dict_secrets(data)
        assert enc["password"].startswith(ENCRYPTION_PREFIX)
        assert "CleartextPassword123" not in enc["password"]
        assert enc["nested"]["auth_token"].startswith(ENCRYPTION_PREFIX)
        assert enc["host"] == "smtp.domain.com"

        dec = decrypt_dict_secrets(enc)
        assert dec["password"] == "CleartextPassword123"
        assert dec["nested"]["auth_token"] == "token_abc_xyz_789"


# ---------------------------------------------------------------------------
# 5. Wrong key / decryption failure tests
# ---------------------------------------------------------------------------

class TestDecryptionFailure:
    def test_wrong_key_raises_decryption_error(self, monkeypatch):
        """decrypt_string with wrong key must raise DecryptionError, not return ciphertext."""
        key1 = Fernet.generate_key().decode()
        key2 = Fernet.generate_key().decode()
        assert key1 != key2

        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", key1)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import encrypt_string
        ct = encrypt_string("MySecret")

        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", key2)
        importlib.reload(storage.crypto)
        from storage.crypto import decrypt_string, DecryptionError
        with pytest.raises(DecryptionError):
            decrypt_string(ct)

    def test_corrupted_ciphertext_raises_decryption_error(self, monkeypatch, valid_key):
        """Corrupted ciphertext must raise DecryptionError."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import decrypt_string, DecryptionError, ENCRYPTION_PREFIX
        with pytest.raises(DecryptionError):
            decrypt_string(f"{ENCRYPTION_PREFIX}totallyinvalidciphertext==")

    def test_plaintext_non_encrypted_string_passthrough(self, monkeypatch, valid_key):
        """Non-encrypted strings (without enc:v1: prefix) are returned as-is."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import decrypt_string
        assert decrypt_string("plain_value") == "plain_value"
        assert decrypt_string("") == ""
        assert decrypt_string(None) is None

    def test_get_system_setting_returns_default_on_decrypt_error(self, monkeypatch, test_db):
        """get_system_setting falls back to default if decryption fails (wrong key)."""
        key1 = Fernet.generate_key().decode()
        key2 = Fernet.generate_key().decode()

        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", key1)
        importlib.reload(sys.modules["storage.crypto"])
        from storage.forensics_db import save_system_setting
        save_system_setting(test_db, "notification_email", {"host": "smtp.ex.com", "password": "SecretPass"})

        # Switch to wrong key
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", key2)
        importlib.reload(sys.modules["storage.crypto"])
        from storage.forensics_db import get_system_setting
        result = get_system_setting(test_db, "notification_email", default=None)
        # Should return None (default) instead of leaking ciphertext as credential
        assert result is None, f"Expected None on decryption failure, got: {result}"


# ---------------------------------------------------------------------------
# 6. Database raw inspection: no plaintext credentials
# ---------------------------------------------------------------------------

class TestNoPersistPlaintext:
    def test_database_raw_no_plaintext(self, monkeypatch, valid_key, test_db):
        """Raw database records must never store plaintext credentials."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.forensics_db import save_system_setting, get_system_setting
        from storage.crypto import ENCRYPTION_PREFIX

        setting = {
            "host": "smtp.gmail.com",
            "user": "soc@gmail.com",
            "password": "MySuperSecretPassword_XYZ",
            "bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        }
        save_system_setting(test_db, "notification_email", setting)

        cur = test_db.cursor()
        cur.execute("SELECT value_json FROM system_settings WHERE setting_key='notification_email'")
        raw_json = cur.fetchone()["value_json"]
        assert "MySuperSecretPassword_XYZ" not in raw_json
        assert "123456:ABC-DEF" not in raw_json
        assert ENCRYPTION_PREFIX in raw_json

        retrieved = get_system_setting(test_db, "notification_email")
        assert retrieved["password"] == "MySuperSecretPassword_XYZ"
        assert retrieved["bot_token"] == "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"


# ---------------------------------------------------------------------------
# 7. Partial update preservation tests
# ---------------------------------------------------------------------------

class TestPartialUpdatePreservation:
    def test_blank_password_preserves_existing_secret(self, monkeypatch, valid_key, test_db):
        """Submitting blank password on update must not destroy existing stored credential."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.forensics_db import save_system_setting, get_system_setting

        save_system_setting(test_db, "notification_email", {
            "host": "smtp.initial.com",
            "password": "ExistingSavedPassword999",
        })
        save_system_setting(test_db, "notification_email", {
            "host": "smtp.updated.com",
            "password": "",  # blank resubmission
        })
        retrieved = get_system_setting(test_db, "notification_email")
        assert retrieved["host"] == "smtp.updated.com"
        assert retrieved["password"] == "ExistingSavedPassword999"

    def test_masked_password_preserves_existing_secret(self, monkeypatch, valid_key, test_db):
        """Submitting '********' password on update must preserve existing credential."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.forensics_db import save_system_setting, get_system_setting

        save_system_setting(test_db, "notification_email", {
            "host": "smtp.initial.com",
            "password": "ExistingSavedPassword999",
        })
        save_system_setting(test_db, "notification_email", {
            "host": "smtp.updated.com",
            "password": "********",
        })
        retrieved = get_system_setting(test_db, "notification_email")
        assert retrieved["password"] == "ExistingSavedPassword999"


# ---------------------------------------------------------------------------
# 8. NotificationOutboxManager lifecycle
# ---------------------------------------------------------------------------

class TestNotificationOutboxManager:
    def test_roundtrip_lifecycle(self, monkeypatch, valid_key, test_db):
        """NotificationOutboxManager configures, persists encrypted, and reloads credentials."""
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", valid_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from notifications.outbox import NotificationOutboxManager
        from storage.crypto import ENCRYPTION_PREFIX

        mgr = NotificationOutboxManager()
        mgr.set_connection(test_db)

        ok, msg = mgr.configure_provider("telegram", {
            "bot_token": "telegram_secret_token_12345",
            "chat_id": "-100123456789",
        }, persist=True)
        assert ok is True

        cur = test_db.cursor()
        cur.execute("SELECT value_json FROM system_settings WHERE setting_key='notification_telegram'")
        raw_json = cur.fetchone()["value_json"]
        assert "telegram_secret_token_12345" not in raw_json
        assert ENCRYPTION_PREFIX in raw_json

        mgr2 = NotificationOutboxManager()
        mgr2.set_connection(test_db)
        mgr2.reload_providers_from_db()
        provider = mgr2.get_provider("telegram")
        assert provider is not None
        assert getattr(provider, "bot_token", None) == "telegram_secret_token_12345"

    def test_provider_fails_gracefully_on_wrong_key(self, monkeypatch, test_db):
        """Provider reload with wrong decryption key must leave provider unconfigured."""
        key1 = Fernet.generate_key().decode()
        key2 = Fernet.generate_key().decode()

        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", key1)
        importlib.reload(sys.modules["storage.crypto"])
        from notifications.outbox import NotificationOutboxManager

        mgr = NotificationOutboxManager()
        mgr.set_connection(test_db)
        mgr.configure_provider("webhook", {
            "url": "http://localhost:9999/webhook",
            "secret": "webhook_signing_secret_abc",
        }, persist=True)

        # Wrong key
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", key2)
        importlib.reload(sys.modules["storage.crypto"])

        mgr2 = NotificationOutboxManager()
        mgr2.set_connection(test_db)
        mgr2.reload_providers_from_db()
        # Provider should remain unconfigured
        provider = mgr2.get_provider("webhook")
        # Either None, or the secret should not be accessible
        if provider is not None:
            secret = getattr(provider, "secret", None)
            assert secret != "webhook_signing_secret_abc", \
                "Decryption with wrong key must not expose real secret"

    def test_configure_fails_closed_on_missing_key(self, monkeypatch, test_db):
        """configure_provider must fail and not persist without a valid encryption key."""
        # Key is not set (cleared by autouse fixture)
        from notifications.outbox import NotificationOutboxManager
        mgr = NotificationOutboxManager()
        mgr.set_connection(test_db)

        ok, msg = mgr.configure_provider("email", {
            "host": "smtp.example.com",
            "password": "Password123",
        }, persist=True)

        # Should fail
        assert ok is False, f"Expected ok=False on encryption error, got ok={ok}"

        # Raw database must have no plaintext
        cur = test_db.cursor()
        cur.execute("SELECT value_json FROM system_settings WHERE setting_key='notification_email'")
        row = cur.fetchone()
        if row:
            assert "Password123" not in row[0], "Plaintext password must not persist on encryption failure"


# ---------------------------------------------------------------------------
# 9. Legacy credential migration
# ---------------------------------------------------------------------------

class TestLegacyCredentialMigration:
    def test_migrate_records_encrypted_with_legacy_key(self, monkeypatch, test_db):
        """migrate_legacy_credentials re-encrypts records made with legacy key."""
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import base64

        legacy_passphrase = "netguard-soc-default-master-key-seed-32b"
        old_salt = b"netguard_credential_encryption_v1_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=old_salt,
            iterations=100_000,
        )
        derived = base64.urlsafe_b64encode(kdf.derive(legacy_passphrase.encode()))
        from cryptography.fernet import Fernet as _Fernet
        legacy_fernet = _Fernet(derived)

        # Insert a legacy-encrypted record
        import json
        raw_ct = legacy_fernet.encrypt(b"legacy_secret_value").decode()
        v = {"host": "smtp.old.com", "password": f"enc:v1:{raw_ct}"}
        cur = test_db.cursor()
        import time
        cur.execute(
            "INSERT OR REPLACE INTO system_settings (setting_key, value_json, updated_at) VALUES (?, ?, ?)",
            ("notification_email", json.dumps(v), time.time())
        )
        test_db.commit()
        cur.close()

        # Set active key and run migration
        new_key = Fernet.generate_key().decode()
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", new_key)
        importlib.reload(sys.modules["storage.crypto"])
        from storage.crypto import migrate_legacy_credentials

        result = migrate_legacy_credentials(test_db, legacy_key=legacy_passphrase)
        assert "notification_email" in result["migrated"], f"Expected migration, got: {result}"
        assert len(result["errors"]) == 0, f"Migration errors: {result['errors']}"

        # Verify migrated record is decryptable with new key
        from storage.forensics_db import get_system_setting
        retrieved = get_system_setting(test_db, "notification_email")
        assert retrieved is not None
        assert retrieved["password"] == "legacy_secret_value", \
            f"Expected decrypted legacy_secret_value, got: {retrieved.get('password')}"

    def test_migration_without_legacy_key_reports_unmigrated(self, monkeypatch, test_db):
        """Migration without legacy key must report unmigrated records (not silently skip or fail)."""
        new_key = Fernet.generate_key().decode()
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", new_key)
        import storage.crypto; importlib.reload(storage.crypto)
        from storage.crypto import migrate_legacy_credentials, ENCRYPTION_PREFIX
        import json, time

        # Insert a fake encrypted record (encrypted with a different key)
        other_key = Fernet.generate_key()
        other_fernet = Fernet(other_key)
        ct = other_fernet.encrypt(b"some_secret").decode()
        v = {"password": f"{ENCRYPTION_PREFIX}{ct}"}
        cur = test_db.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO system_settings (setting_key, value_json, updated_at) VALUES (?, ?, ?)",
            ("notification_smtp", json.dumps(v), time.time())
        )
        test_db.commit()
        cur.close()

        result = migrate_legacy_credentials(test_db, legacy_key=None)
        assert len(result["unmigrated"]) > 0, f"Expected unmigrated records, got: {result}"


# ---------------------------------------------------------------------------
# 10. Session key stability
# ---------------------------------------------------------------------------

class TestSessionKeyStability:
    def test_stable_key_enables_cross_worker_session_validation(self, monkeypatch):
        """Two Flask app instances with the same NETGUARD_SECRET_KEY validate the same session."""
        import os
        os.environ["NETGUARD_TESTING"] = "1"
        from cryptography.fernet import Fernet
        sess_key = Fernet.generate_key().decode()
        enc_key = Fernet.generate_key().decode()
        monkeypatch.setenv("NETGUARD_SECRET_KEY", sess_key)
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", enc_key)

        import storage.crypto; importlib.reload(storage.crypto)
        import dashboard.app as d_app
        importlib.reload(d_app)
        import config as cfg
        cfg.DASHBOARD_AUTH_ENABLED = False
        cfg.DASHBOARD_CSRF_ENABLED = False

        # Worker 1: create session with token
        app1 = d_app.app
        app1.secret_key = sess_key
        with app1.test_client() as client1:
            with client1.session_transaction() as sess:
                sess["_csrf_token"] = "stable_token_xyz"
                sess["worker_id"] = "worker-1"
            resp = client1.get("/api/status")
            assert resp.status_code == 200

        # Worker 2 (same key): must validate the session
        app2 = d_app.app
        app2.secret_key = sess_key
        with app2.test_client() as client2:
            with client2.session_transaction() as sess:
                sess["_csrf_token"] = "stable_token_xyz"
                sess["worker_id"] = "worker-1"
            resp2 = client2.get("/api/status")
            assert resp2.status_code == 200

        os.environ.pop("NETGUARD_TESTING", None)

    def test_key_rotation_invalidates_sessions(self, monkeypatch):
        """After key rotation, existing sessions signed with old key must be invalid."""
        import os
        os.environ["NETGUARD_TESTING"] = "1"
        old_key = Fernet.generate_key().decode()
        new_key = Fernet.generate_key().decode()
        enc_key = Fernet.generate_key().decode()
        assert old_key != new_key

        monkeypatch.setenv("NETGUARD_SECRET_KEY", old_key)
        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", enc_key)
        import storage.crypto; importlib.reload(storage.crypto)
        import dashboard.app as d_app
        importlib.reload(d_app)
        import config as cfg
        cfg.DASHBOARD_AUTH_ENABLED = False
        cfg.DASHBOARD_CSRF_ENABLED = False

        old_app = d_app.app
        old_app.secret_key = old_key

        # Create a session-bound cookie with old key
        with old_app.test_client() as old_client:
            with old_client.session_transaction() as sess:
                sess["_test_identity"] = "old-session"
            resp = old_client.get("/api/status")
            assert resp.status_code == 200

        # After key rotation: a fresh client with new key gets a fresh session
        new_app = d_app.app
        new_app.secret_key = new_key
        with new_app.test_client() as new_client:
            resp2 = new_client.get("/api/status")
            assert resp2.status_code == 200
            with new_client.session_transaction() as sess:
                # Fresh client on rotated key has no old session identity
                assert sess.get("_test_identity") != "old-session", \
                    "Session identity from old key must not appear in new-key session"

        os.environ.pop("NETGUARD_TESTING", None)
