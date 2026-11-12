"""
ids_project/tests/test_session_csrf_security.py
-----------------------------------------------
Security verification for session-bound CSRF token protection.
Tests two independent client sessions to verify:
- Distinct session tokens
- Cross-session token rejection (Session A token rejected in Session B)
- Missing and forged tokens return HTTP 403
- Valid session tokens succeed
"""

import os
import sys
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from dashboard.app import app
from storage.db import get_connection, init_db
from storage.forensics_db import init_forensics_db


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Ensure isolated SQLite database for CSRF test."""
    orig_backend = config.DB_BACKEND
    orig_sqlite = config.SQLITE_PATH
    config.DB_BACKEND = "sqlite"
    test_db = str(tmp_path / "csrf_test.db")
    config.SQLITE_PATH = test_db

    import dashboard.app as d_app
    if d_app._db_conn:
        try:
            d_app._db_conn.close()
        except Exception:
            pass
        d_app._db_conn = None

    conn = get_connection()
    init_db(conn)
    init_forensics_db(conn)
    conn.close()

    yield

    if d_app._db_conn:
        try:
            d_app._db_conn.close()
        except Exception:
            pass
        d_app._db_conn = None

    config.DB_BACKEND = orig_backend
    config.SQLITE_PATH = orig_sqlite


@pytest.fixture(autouse=True)
def enable_csrf_for_tests():
    """Explicitly enable CSRF enforcement for this security test suite."""
    old_enforce = getattr(config, "DASHBOARD_CSRF_ENFORCE_IN_TESTS", False)
    old_csrf = getattr(config, "DASHBOARD_CSRF_ENABLED", True)
    config.DASHBOARD_CSRF_ENFORCE_IN_TESTS = True
    config.DASHBOARD_CSRF_ENABLED = True
    yield
    config.DASHBOARD_CSRF_ENFORCE_IN_TESTS = old_enforce
    config.DASHBOARD_CSRF_ENABLED = old_csrf


def test_session_scoped_csrf_isolation():
    """Verify session isolation, distinct tokens, and cross-session CSRF blocking."""
    # Create two independent clients representing two different browser sessions
    client_a = app.test_client()
    client_b = app.test_client()

    # 1. Fetch CSRF token for Session A
    res_a = client_a.get("/api/csrf-token")
    assert res_a.status_code == 200
    token_a = res_a.get_json()["csrf_token"]
    assert token_a and len(token_a) >= 16

    # 2. Fetch CSRF token for Session B
    res_b = client_b.get("/api/csrf-token")
    assert res_b.status_code == 200
    token_b = res_b.get_json()["csrf_token"]
    assert token_b and len(token_b) >= 16

    # Sessions must receive distinct tokens
    assert token_a != token_b

    # 3. Session A uses its own valid token on a mutating route -> 200 OK
    res_valid_a = client_a.post(
        "/api/cases",
        json={"title": "Case by Session A", "severity": "medium"},
        headers={"X-CSRFToken": token_a}
    )
    assert res_valid_a.status_code == 200

    # 4. Session B uses Session A's token (Cross-Session attack) -> 403 Forbidden
    res_cross = client_b.post(
        "/api/cases",
        json={"title": "Attacker Case", "severity": "high"},
        headers={"X-CSRFToken": token_a}
    )
    assert res_cross.status_code == 403
    assert "CSRF token missing or invalid" in res_cross.get_json()["error"]

    # 5. Missing CSRF token -> 403 Forbidden
    res_missing = client_a.post(
        "/api/cases",
        json={"title": "Missing Token Case", "severity": "low"}
    )
    assert res_missing.status_code == 403
    assert "CSRF token missing or invalid" in res_missing.get_json()["error"]

    # 6. Forged / Random token -> 403 Forbidden
    res_forged = client_a.post(
        "/api/cases",
        json={"title": "Forged Token Case", "severity": "low"},
        headers={"X-CSRFToken": "forged_random_hex_1234567890"}
    )
    assert res_forged.status_code == 403

    # 7. Session B uses its own valid token -> 200 OK
    res_valid_b = client_b.post(
        "/api/cases",
        json={"title": "Case by Session B", "severity": "medium"},
        headers={"X-CSRFToken": token_b}
    )
    assert res_valid_b.status_code == 200
