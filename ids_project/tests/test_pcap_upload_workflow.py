"""
Unit and integration tests for PCAP Upload Workflow and Isolated Analysis Replay.
"""

import os
import sys
import io
import time
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from dashboard.app import app
from storage.db import get_connection, init_db
from storage.forensics_db import init_forensics_db
import config


@pytest.fixture(autouse=True)
def setup_isolated_db(tmp_path):
    orig_sqlite = config.SQLITE_PATH
    orig_backend = config.DB_BACKEND
    db_file = str(tmp_path / "test_pcap.db")
    config.DB_BACKEND = "sqlite"
    config.SQLITE_PATH = db_file

    import dashboard.app as d_app
    d_app._db_conn = None
    d_app._offline_analyzer = None

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
    d_app._offline_analyzer = None

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


def test_pcap_upload_rejected_without_file(client, auth_headers):
    res = client.post("/api/pcap/upload", headers=auth_headers, data={}, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "No file uploaded" in res.get_json()["error"]


def test_pcap_upload_rejected_invalid_extension(client, auth_headers):
    data = {
        "file": (io.BytesIO(b"dummy data"), "capture.exe")
    }
    res = client.post("/api/pcap/upload", headers=auth_headers, data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "Invalid extension" in res.get_json()["error"]


def test_pcap_upload_rejected_corrupt_magic_bytes(client, auth_headers):
    corrupt_data = b"NOT_A_REAL_PCAP_HEADER_DATA_STREAM"
    data = {
        "file": (io.BytesIO(corrupt_data), "corrupt.pcap")
    }
    res = client.post("/api/pcap/upload", headers=auth_headers, data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "Invalid PCAP" in res.get_json()["error"] or "magic header" in res.get_json()["error"].lower()


def test_pcap_upload_valid_magic_bytes_queued(client, auth_headers):
    # Standard PCAP global header magic number: 0xd4c3b2a1 (little endian)
    pcap_header = (
        b"\xd4\xc3\xb2\xa1"  # magic_number
        b"\x02\x00"          # version_major
        b"\x04\x00"          # version_minor
        b"\x00\x00\x00\x00"  # thiszone
        b"\x00\x00\x00\x00"  # sigfigs
        b"\x00\x00\x04\x00"  # snaplen (262144)
        b"\x01\x00\x00\x00"  # network (LINKTYPE_ETHERNET)
    )
    data = {
        "file": (io.BytesIO(pcap_header), "valid_empty.pcap")
    }
    res = client.post("/api/pcap/upload", headers=auth_headers, data=data, content_type="multipart/form-data")
    assert res.status_code in (200, 202)
    resp = res.get_json()
    assert "job_id" in resp
    job_id = resp["job_id"]

    # Test job status retrieval
    res_job = client.get(f"/api/pcap/jobs/{job_id}")
    assert res_job.status_code == 200
    job_data = res_job.get_json()
    job = job_data.get("job") or job_data
    assert job["job_id"] == job_id


def test_pcap_jobs_list(client):
    res = client.get("/api/pcap/jobs")
    assert res.status_code == 200
    jobs = res.get_json()
    assert isinstance(jobs, list)


def test_pcap_job_export(client):
    # Nonexistent job should return 404
    res = client.get("/api/pcap/jobs/nonexistent_job_123/export?format=json")
    assert res.status_code == 404
