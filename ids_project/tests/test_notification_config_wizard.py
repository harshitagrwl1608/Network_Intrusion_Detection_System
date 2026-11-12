"""
Unit and integration tests for Notification Configuration Wizard and Provider Outbox.
Verifies sender/recipient distinction, secret masking, persistent settings, and test diagnostics.
"""

import os
import sys
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from dashboard.app import app
from storage.forensics_db import get_system_setting, save_system_setting, init_forensics_db
from storage.db import get_connection, init_db
import config


@pytest.fixture(autouse=True)
def setup_isolated_db(tmp_path):
    orig_sqlite = config.SQLITE_PATH
    orig_backend = config.DB_BACKEND
    db_file = str(tmp_path / "test_notif.db")
    config.DB_BACKEND = "sqlite"
    config.SQLITE_PATH = db_file

    import dashboard.app as d_app
    d_app._db_conn = None

    conn = get_connection()
    init_db(conn)
    init_forensics_db(conn)
    conn.close()

    yield

    if d_app._db_conn is not None:
        try:
            d_app._db_conn.close()
        except Exception:
            pass
        d_app._db_conn = None

    config.SQLITE_PATH = orig_sqlite
    config.DB_BACKEND = orig_backend


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers(client):
    res = client.get("/api/csrf-token")
    token = res.get_json()["csrf_token"]
    return {"X-CSRFToken": token}


def test_notification_config_get_masked(client):
    res = client.get("/api/notifications/config")
    assert res.status_code == 200
    configs = res.get_json()
    assert "email" in configs
    assert "telegram" in configs
    assert "webhook" in configs
    assert "sms" in configs

    # Verify no raw password leaked
    email_cfg = configs["email"]
    assert "password" not in email_cfg
    assert "password_set" in email_cfg


def test_notification_config_save_smtp_sender_recipient_distinct(client, auth_headers):
    # Distinct sender (from_addr) and recipient (to_addr)
    payload = {
        "provider": "email",
        "config": {
            "host": "smtp.gmail.com",
            "port": 587,
            "user": "alerts-sender@corp.internal",
            "password": "SuperSecretAppPassword123",
            "from_addr": "netguard-daemon@corp.internal",
            "to_addr": "soc-team@corp.internal",
            "use_tls": True
        }
    }
    res = client.post("/api/notifications/config", headers=auth_headers, json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    cfg = data["config"]
    assert cfg["from_addr"] == "netguard-daemon@corp.internal"
    assert cfg["to_addr"] == "soc-team@corp.internal"
    assert cfg["user"] == "alerts-sender@corp.internal"
    assert cfg["password_set"] is True
    assert "SuperSecretAppPassword123" not in str(cfg)

    # Verify persistence in system_settings table
    conn = get_connection()
    persisted = get_system_setting(conn, "notification_email")
    assert persisted is not None
    assert persisted["from_addr"] == "netguard-daemon@corp.internal"
    assert persisted["to_addr"] == "soc-team@corp.internal"


def test_notification_config_save_webhook(client, auth_headers):
    payload = {
        "provider": "webhook",
        "config": {
            "url": "https://siem.corp.internal/api/v1/netguard-alerts",
            "secret": "hmac_signing_key_456"
        }
    }
    res = client.post("/api/notifications/config", headers=auth_headers, json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    cfg = data["config"]
    assert cfg["url"] == "https://siem.corp.internal/api/v1/netguard-alerts"
    assert cfg["secret_set"] is True


def test_notification_test_diagnostic_dispatch(client, auth_headers):
    payload = {
        "provider": "webhook",
        "recipient": "http://127.0.0.1:9999/null-webhook",
        "config": {
            "url": "http://127.0.0.1:9999/null-webhook"
        }
    }
    res = client.post("/api/notifications/test", headers=auth_headers, json=payload)
    assert res.status_code == 200
    data = res.get_json()
    # It might fail to connect to 127.0.0.1:9999, but must return a structured response rather than crash
    assert "success" in data or "status" in data

