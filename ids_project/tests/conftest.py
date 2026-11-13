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
import sys

import pytest
from cryptography.fernet import Fernet

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

# Baseline for ``engine.rules.TRUSTED_HOSTS``.  The set is empty at import time;
# RuleEngine instances populate it from config.TRUSTED_HOSTS (which includes the
# configured gateway).  Captured once so per-test cleanup can restore it.
_TRUSTED_HOSTS_BASELINE: set = set()


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


@pytest.fixture(autouse=True)
def isolate_engine_trusted_hosts():
    """Restore ``engine.rules.TRUSTED_HOSTS`` to its session baseline after every test.

    ``RuleEngine.__init__`` copies ``config.TRUSTED_HOSTS`` into the
    module-global ``engine.rules.TRUSTED_HOSTS`` set.  ``config`` seeds that set
    with the configured gateway (``GATEWAY_IP``, default ``192.168.1.1``), so any
    test that constructs an engine silently marks the gateway as trusted for the
    remainder of the session.  Detection tests that legitimately expect an alert
    from that address then fail depending on collection order (for example the
    TCP zero-window responder-role test, whose advertiser is ``192.168.1.1``).

    Class-scoped setup (``setUpClass``) runs outside the per-test fixture window,
    so the restore target is the fixed session baseline
    (``_TRUSTED_HOSTS_BASELINE``) rather than the value seen at test start.
    Restoring the baseline keeps every test hermetic without changing production
    behaviour or weakening any assertion.
    """
    try:
        import engine.rules as rules_mod
    except Exception:  # pragma: no cover - engine unavailable in this context
        yield
        return

    try:
        yield
    finally:
        rules_mod.TRUSTED_HOSTS.clear()
        rules_mod.TRUSTED_HOSTS.update(_TRUSTED_HOSTS_BASELINE)
