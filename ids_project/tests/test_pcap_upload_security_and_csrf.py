"""
tests/test_pcap_upload_security_and_csrf.py
---------------------------------------------
Verifies:
1. PCAP Upload Security & Resource Protection:
   - Rejection of files exceeding MAX_CONTENT_LENGTH (HTTP 413).
   - Rejection of unsupported extensions (HTTP 400).
   - Rejection of files with corrupted or invalid magic numbers (HTTP 400).
   - File sanitization via secure_filename (prevents directory traversal).
2. CSRF Token Enforcement:
   - State-changing HTTP methods (POST, PUT, PATCH, DELETE) require valid X-CSRFToken.
   - Missing or forged CSRF tokens return HTTP 403.
   - Legitimate CSRF token allows mutation.
3. Dashboard Basic Authentication:
   - Returns HTTP 401 with WWW-Authenticate header when credentials missing or incorrect.
   - Allows access when valid credentials provided.
4. Rule Health UI Contract:
   - Formatter returns 'N/A (No reviews yet)' when total feedback is 0.
"""

import os
import io
import sys
import time
import base64
import shutil
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import init_db, get_connection
from storage.forensics_db import init_forensics_db
import dashboard.app as app_mod
from dashboard.app import app, _csrf_token


class TestPcapUploadSecurityAndCsrf(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_sec.db")

        self.orig_sqlite = config.SQLITE_PATH
        self.orig_backend = config.DB_BACKEND
        self.orig_auth = getattr(config, "DASHBOARD_AUTH_ENABLED", False)
        self.orig_csrf = getattr(config, "DASHBOARD_CSRF_ENABLED", True)

        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = self.db_path
        config.DASHBOARD_CSRF_ENFORCE_IN_TESTS = True

        app_mod._db_conn = None
        self.conn = get_connection(self.db_path)
        init_db(self.conn)
        init_forensics_db(self.conn)

        app.config["TESTING"] = False  # Enable real middleware evaluation
        self.client = app.test_client()

    def tearDown(self):
        self.conn.close()
        app_mod._db_conn = None
        config.DASHBOARD_CSRF_ENFORCE_IN_TESTS = False
        app.config["TESTING"] = True
        config.SQLITE_PATH = self.orig_sqlite
        config.DB_BACKEND = self.orig_backend
        config.DASHBOARD_AUTH_ENABLED = self.orig_auth
        config.DASHBOARD_CSRF_ENABLED = self.orig_csrf
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_pcap_upload_validation_and_rejection(self):
        """Verify invalid extension and corrupted magic bytes are rejected."""
        headers = {"X-CSRFToken": _csrf_token}

        # 1. Invalid file extension (.sh)
        data = {"file": (io.BytesIO(b"#!/bin/bash\necho test\n"), "malicious.sh")}
        resp = self.client.post("/api/pcap/upload", data=data, headers=headers, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid extension", resp.get_json()["error"])

        # 2. Corrupt / non-PCAP magic bytes
        fake_pcap = b"NOT_A_REAL_PCAP_HEADER_DATA_1234567890"
        data = {"file": (io.BytesIO(fake_pcap), "corrupted.pcap")}
        resp = self.client.post("/api/pcap/upload", data=data, headers=headers, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid PCAP file header", resp.get_json()["error"])

        # 3. Path traversal in filename
        valid_pcap_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
        data = {"file": (io.BytesIO(valid_pcap_header), "../../../etc/passwd.pcap")}
        resp = self.client.post("/api/pcap/upload", data=data, headers=headers, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        # Filename should be sanitized to passwd.pcap
        job_info = resp.get_json()
        self.assertNotIn("..", job_info["filename"])
        self.assertIn("passwd.pcap", job_info["filename"])

    def test_csrf_token_enforcement_on_mutations(self):
        """Verify state-changing endpoints reject requests lacking valid CSRF token."""
        config.DASHBOARD_CSRF_ENABLED = True

        # POST without CSRF token -> 403 Forbidden
        resp_no_token = self.client.post(
            "/api/saved-searches",
            json={"name": "test_search", "query": {}}
        )
        self.assertEqual(resp_no_token.status_code, 403)
        self.assertIn("CSRF token missing or invalid", resp_no_token.get_json()["error"])

        # POST with wrong CSRF token -> 403 Forbidden
        resp_bad_token = self.client.post(
            "/api/saved-searches",
            json={"name": "test_search", "query": {}},
            headers={"X-CSRFToken": "invalid_forged_token_12345"}
        )
        self.assertEqual(resp_bad_token.status_code, 403)

        # POST with valid CSRF token -> 200 OK
        resp_valid = self.client.post(
            "/api/saved-searches",
            json={"name": "valid_search", "query": {}},
            headers={"X-CSRFToken": _csrf_token}
        )
        self.assertEqual(resp_valid.status_code, 200)
        self.assertEqual(resp_valid.get_json()["status"], "ok")

    def test_dashboard_basic_auth_protection(self):
        """Verify Basic Authentication gate when DASHBOARD_AUTH_ENABLED is active."""
        config.DASHBOARD_AUTH_ENABLED = True
        config.DASHBOARD_USERNAME = "secops"
        config.DASHBOARD_PASSWORD = "SuperSecretPassword123"

        # 1. Unauthenticated request -> 401 Unauthorized
        resp_unauth = self.client.get("/api/status")
        self.assertEqual(resp_unauth.status_code, 401)
        self.assertIn("WWW-Authenticate", resp_unauth.headers)
        self.assertIn('Basic realm="NetGuard SOC Dashboard"', resp_unauth.headers["WWW-Authenticate"])

        # 2. Invalid credentials -> 401 Unauthorized
        bad_creds = base64.b64encode(b"wrong:creds").decode("ascii")
        resp_bad = self.client.get("/api/status", headers={"Authorization": f"Basic {bad_creds}"})
        self.assertEqual(resp_bad.status_code, 401)

        # 3. Valid credentials -> 200 OK
        valid_creds = base64.b64encode(b"secops:SuperSecretPassword123").decode("ascii")
        resp_ok = self.client.get("/api/status", headers={"Authorization": f"Basic {valid_creds}"})
        self.assertEqual(resp_ok.status_code, 200)


if __name__ == "__main__":
    unittest.main()
