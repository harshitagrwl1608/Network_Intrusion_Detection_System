"""
ids_project/tests/conftest.py
------------------------------
Shared pytest fixtures and session-level configuration for the NetGuard IDS test suite.

Key responsibilities:
- Inject distinct, cryptographically-valid NETGUARD_ENCRYPTION_KEY and NETGUARD_SECRET_KEY
  environment variables before any test module is imported, so that tests which call
  save_system_setting() or encrypt_string() work without hardcoded fallbacks.
- Set NETGUARD_TESTING=1 to suppress the production-mode RuntimeWarning from app.py.
- Use os.environ.setdefault() so that:
    - Individual test monkeypatches can still override both keys for crypto-failure tests.
    - Explicitly provided env vars (e.g. CI secrets) are not overwritten.

Security note:
  These are ephemeral, randomly-generated keys used only during the test session.
  They are NEVER persisted, logged, or reused across runs.
  The two keys are always distinct (enforced by generate twice + re-roll if equal).
"""

import os
import pytest
from cryptography.fernet import Fernet


def _generate_distinct_keys():
    """Generate two distinct Fernet keys for the session."""
    enc_key = Fernet.generate_key().decode()
    sess_key = Fernet.generate_key().decode()
    # Extremely unlikely to collide, but enforce distinctness explicitly
    while enc_key == sess_key:
        sess_key = Fernet.generate_key().decode()
    return enc_key, sess_key


def pytest_configure(config):
    """
    pytest_configure hook: runs BEFORE test collection and module imports.

    This is the earliest hook available in pytest, ensuring that environment
    variables are set before app.py (or any other module) is imported during
    collection. This prevents the NETGUARD_SECRET_KEY RuntimeWarning from firing
    when tests are collected.

    Uses setdefault() so explicitly provided CI/environment values are preserved.
    """
    enc_key, sess_key = _generate_distinct_keys()
    os.environ.setdefault("NETGUARD_ENCRYPTION_KEY", enc_key)
    os.environ.setdefault("NETGUARD_SECRET_KEY", sess_key)
    # Signal test mode so app.py skips the production RuntimeWarning
    os.environ.setdefault("NETGUARD_TESTING", "1")


@pytest.fixture(autouse=True, scope="session")
def set_test_crypto_keys():
    """
    Session-scoped autouse fixture: confirm that crypto keys are set
    (they were injected via pytest_configure, but this fixture ensures the
    contract is visible and can be overridden at the fixture level for
    individual test modules that use monkeypatch).
    """
    # Keys are already set by pytest_configure; this fixture is a no-op for
    # normal tests but ensures the contract is enforced at fixture level too.
    assert os.environ.get("NETGUARD_ENCRYPTION_KEY"), \
        "NETGUARD_ENCRYPTION_KEY must be set (via pytest_configure or CI environment)"
    assert os.environ.get("NETGUARD_SECRET_KEY"), \
        "NETGUARD_SECRET_KEY must be set (via pytest_configure or CI environment)"
    assert os.environ.get("NETGUARD_TESTING") == "1", \
        "NETGUARD_TESTING must be '1' during test sessions"
    yield

    # Note: we do NOT clear the keys after the session because other test cleanup
    # may still need them (e.g., teardown fixtures). The process ends after the
    # test session anyway, so there is no security concern about leaving them set.
