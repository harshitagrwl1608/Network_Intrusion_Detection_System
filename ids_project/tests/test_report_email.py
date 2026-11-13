"""
tests/test_report_email.py
--------------------------
Focused tests for the "Generate & Email" report workflow.

Coverage:

1. Report generator safety and format policy
   - HTML/JSON/CSV only; a ``pdf`` request degrades to HTML, never to a
     mislabelled ``.html`` file pretending to be a PDF
   - HTML escaping of attacker-controlled alert fields
   - CSV formula-injection neutralisation
2. Report artifact handling
   - generation confined to the application artifact directory
   - restrictive file mode, SHA-256 and size recorded
   - attachment path validation rejects traversal/escaping
   - size ceiling and pruning
3. Outbox report delivery
   - report job renders and delivers through SMTP with an attachment
   - missing attachment degrades to a covering email instead of failing
   - permanent SMTP failures are not retried; transient ones are retried
"""

from __future__ import annotations

import email
import json
import os
import shutil
from email import policy
import sqlite3
import sys
import tempfile
import time
from unittest.mock import patch

import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)
if os.path.dirname(__file__) not in sys.path:
    sys.path.insert(0, os.path.dirname(__file__))

import config  # noqa: E402
from storage.db import get_connection, init_db, write_alert  # noqa: E402
from storage.forensics_db import init_forensics_db  # noqa: E402
from reports.generator import (  # noqa: E402
    SUPPORTED_FORMATS,
    ReportGenerator,
    _csv_safe,
)
from notifications.report_delivery import (  # noqa: E402
    MAX_ATTACHMENT_BYTES,
    ReportArtifact,
    ReportDeliveryError,
    ReportTooLargeError,
    artifact_root,
    build_report_payload,
    dump_payload,
    generate_artifact,
    prune_artifacts,
    resolve_artifact_path,
    safe_filename,
)
from notifications.outbox import NotificationOutboxManager  # noqa: E402
from notifications.providers import EmailProvider  # noqa: E402
from smtp_test_server import FakeSmtpServer  # noqa: E402


SMTP_ENV_VARS = (
    "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD",
    "SMTP_FROM", "SMTP_FROM_NAME", "SMTP_TO", "SMTP_CC", "SMTP_BCC",
)


@pytest.fixture
def workdir(monkeypatch, tmp_path):
    """Isolated SQLite database plus report artifact directory.

    A fresh artifact directory is created explicitly because pytest's
    ``tmp_path`` may be reused between sessions and can contain stale files.
    """
    db_path = str(tmp_path / "netguard.db")
    artifact_dir = tempfile.mkdtemp(prefix="netguard_artifacts_")
    shutil.rmtree(artifact_dir, ignore_errors=True)
    os.makedirs(artifact_dir, mode=0o700)

    monkeypatch.setattr(config, "DB_BACKEND", "sqlite")
    monkeypatch.setattr(config, "SQLITE_PATH", db_path)
    monkeypatch.setenv("REPORT_ARTIFACT_DIR", artifact_dir)
    for var in SMTP_ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    conn = get_connection(db_path)
    init_db(conn)
    init_forensics_db(conn)
    try:
        yield {"conn": conn, "db_path": db_path, "artifact_dir": artifact_dir}
    finally:
        try:
            conn.close()
        except Exception:
            pass
        shutil.rmtree(artifact_dir, ignore_errors=True)


@pytest.fixture
def empty_generator(workdir):
    return ReportGenerator(conn=workdir["conn"])


def _seed_alert(conn, **overrides):
    now = time.time()
    alert = {
        "timestamp": now,
        "rule_name": "PORT_SCAN_DETECTED",
        "rule_version": "1.0",
        "src_ip": "192.0.2.10",
        "dst_ip": "192.0.2.50",
        "src_port": 40000,
        "dst_port": 22,
        "protocol": "TCP",
        "detail": "Sequential port sweep observed",
        "severity": "high",
        "confidence": 0.92,
        "evidence_json": json.dumps({"note": "synthetic test evidence"}),
        "window_start": now - 5,
        "window_end": now,
    }
    alert.update(overrides)
    write_alert(conn, alert)
    conn.commit()
    return alert


def _decoded_body(raw: bytes) -> str:
    """Return the concatenated decoded text/attachment names of a message."""
    msg = email.message_from_bytes(raw, policy=policy.default)
    chunks: list[str] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        payload = part.get_payload(decode=True) or b""
        chunks.append(payload.decode("utf-8", "replace"))
        filename = part.get_filename()
        if filename:
            chunks.append(filename)
    return "\n".join(chunks)


class _StubGenerator:
    """Minimal stand-in for ReportGenerator in artifact tests."""

    def __init__(self, content=b"<html>report</html>", mime="text/html",
                 filename="netguard_daily_report.html"):
        self.content = content
        self.mime = mime
        self.filename = filename
        self.calls = []

    def generate(self, report_type="daily", hours=24, fmt="html", case_id=None):
        self.calls.append((report_type, hours, fmt, case_id))
        return self.mime, self.filename, self.content


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------
class TestReportGeneratorFormats:
    def test_supported_formats_are_html_json_csv_only(self):
        assert SUPPORTED_FORMATS == ("html", "json", "csv")
        assert "pdf" not in SUPPORTED_FORMATS

    def test_pdf_request_degrades_to_real_html(self, empty_generator):
        mime, filename, content = empty_generator.generate(fmt="pdf")
        assert mime == "text/html"
        assert filename.endswith(".html")
        assert not filename.endswith(".pdf")
        assert "<html" in content.lower()

    def test_json_report_is_parseable(self, empty_generator):
        mime, filename, content = empty_generator.generate(fmt="json")
        assert mime == "application/json"
        assert filename.endswith(".json")
        parsed = json.loads(content)
        assert parsed["report_type"] == "daily"
        assert "stats" in parsed

    def test_csv_report_has_expected_header(self, empty_generator):
        mime, filename, content = empty_generator.generate(fmt="csv")
        assert mime == "text/csv"
        assert filename.endswith(".csv")
        assert content.startswith("# NetGuard IDS Security Report Export")

    def test_unknown_report_type_is_normalised(self, empty_generator):
        _, _, content = empty_generator.generate(report_type="not-a-type", fmt="json")
        assert json.loads(content)["report_type"] == "daily"


class TestReportEscaping:
    def test_html_report_escapes_alert_fields(self, workdir):
        generator = ReportGenerator(conn=workdir["conn"])
        _seed_alert(
            workdir["conn"],
            rule_name="<script>alert('xss')</script>",
            detail="<img src=x onerror=alert(1)>",
            src_ip="192.0.2.10",
        )
        _, _, content = generator.generate(fmt="html")
        assert "<script>alert('xss')</script>" not in content
        assert "&lt;script&gt;alert" in content
        assert "<img src=x onerror=alert(1)>" not in content
        assert "&lt;img src=x" in content

    def test_severity_is_constrained_for_css_classes(self, workdir):
        generator = ReportGenerator(conn=workdir["conn"])
        _seed_alert(
            workdir["conn"],
            rule_name="SUSPICIOUS_BEACONING",
            severity='high" onmouseover="alert(1)',
        )
        _, _, content = generator.generate(fmt="html")
        assert 'onmouseover="alert(1)' not in content
        assert "medium" in content

    @pytest.mark.parametrize("value", [
        "=cmd|' /C calc'!A0",
        "+1+2",
        "-2-3",
        "@SUM(A1:A2)",
        "\tleading-tab",
        "\rcarriage-return",
    ])
    def test_csv_formula_injection_neutralised(self, value):
        assert _csv_safe(value).startswith("'")

    def test_csv_formula_injection_through_generator(self, workdir):
        generator = ReportGenerator(conn=workdir["conn"])
        _seed_alert(workdir["conn"], rule_name="=HYPERLINK(\"http://evil\",\"x\")")
        _, _, content = generator.generate(fmt="csv")
        assert "\n'=HYPERLINK" in content or ",=HYPERLINK" not in content

    def test_plain_values_are_not_mangled(self):
        assert _csv_safe("PORT_SCAN_DETECTED") == "PORT_SCAN_DETECTED"
        assert _csv_safe(42) == 42
        assert _csv_safe(None) == ""


# ---------------------------------------------------------------------------
# Artifact handling
# ---------------------------------------------------------------------------
class TestReportArtifacts:
    @pytest.fixture(autouse=True)
    def _isolate_artifacts(self, workdir):
        """Every test in this class runs against an isolated artifact root."""
        return workdir

    def test_artifact_root_honours_env_override(self, workdir):
        root = artifact_root()
        assert os.path.isdir(root)
        assert root == os.path.realpath(workdir["artifact_dir"])
        assert os.listdir(root) == []

    def test_generate_artifact_is_confined_and_hashed(self, workdir):
        generator = _StubGenerator(content=b"col1,col2\n1,2\n",
                                   mime="text/csv",
                                   filename="netguard_daily_report.csv")
        artifact = generate_artifact(generator, "daily", 24, "csv")
        root = artifact_root()

        assert artifact.path.startswith(root + os.sep)
        assert os.path.isfile(artifact.path)
        assert artifact.filename == "netguard_daily_report.csv"
        assert artifact.mime == "text/csv"
        assert artifact.size_bytes == len(b"col1,col2\n1,2\n")
        assert len(artifact.sha256) == 64
        assert oct(os.stat(artifact.path).st_mode & 0o777) == "0o600"
        assert generator.calls == [("daily", 24, "csv", None)]

    def test_artifact_filename_uniqueness(self):
        generator = _StubGenerator()
        first = generate_artifact(generator, "daily", 24, "html")
        second = generate_artifact(generator, "daily", 24, "html")
        assert first.path != second.path

    def test_oversized_report_is_rejected(self):
        generator = _StubGenerator(content=b"x" * 64)
        with patch("notifications.report_delivery.MAX_ATTACHMENT_BYTES", 16):
            with pytest.raises(ReportTooLargeError):
                generate_artifact(generator, "daily", 24, "html")

    def test_resolve_accepts_generated_artifact(self):
        artifact = generate_artifact(_StubGenerator(), "daily", 24, "html")
        assert resolve_artifact_path(artifact.path) == artifact.path

    @pytest.mark.parametrize("path", [
        "/etc/passwd",
        "relative/path.html",
        "",
        "/tmp/\x00evil",
    ])
    def test_resolve_rejects_unsafe_references(self, path):
        with pytest.raises(ReportDeliveryError):
            resolve_artifact_path(path)

    def test_resolve_rejects_missing_file_inside_root(self):
        root = artifact_root()
        with pytest.raises(ReportDeliveryError):
            resolve_artifact_path(os.path.join(root, "does-not-exist.html"))

    def test_resolve_rejects_symlink_escape(self, workdir, tmp_path):
        artifact = generate_artifact(_StubGenerator(), "daily", 24, "html")
        secret = tmp_path / "secret.txt"
        secret.write_text("secret", encoding="utf-8")
        link = os.path.join(artifact_root(), "escape.html")
        os.symlink(str(secret), link)
        with pytest.raises(ReportDeliveryError):
            resolve_artifact_path(link)

    def test_prune_removes_stale_artifacts(self):
        artifact = generate_artifact(_StubGenerator(), "daily", 24, "html")
        assert prune_artifacts(max_age_s=3600, max_files=200) == 0
        old = time.time() - 7200
        os.utime(artifact.path, (old, old))
        removed = prune_artifacts(max_age_s=3600, max_files=200)
        assert removed >= 1
        assert not os.path.exists(artifact.path)

    def test_prune_enforces_file_count(self):
        paths = [generate_artifact(_StubGenerator(), "daily", 24, "html").path
                 for _ in range(4)]
        removed = prune_artifacts(max_age_s=86400, max_files=1)
        assert removed == 3
        assert len([p for p in paths if os.path.exists(p)]) == 1

    def test_safe_filename_strips_dangerous_components(self):
        assert safe_filename("../../etc/passwd") == "passwd"
        assert "/" not in safe_filename("a/b/c.html")
        assert safe_filename("") == "netguard_report"


class TestReportPayload:
    def test_payload_is_bounded(self):
        artifact = ReportArtifact(
            path="/tmp/x.html", filename="x.html", mime="text/html",
            size_bytes=10, sha256="0" * 64,
        )
        rows = [(f"metric-{i}" * 20, "value" * 100) for i in range(40)]
        payload = build_report_payload(
            artifact, report_title="Daily" * 100, report_type="daily",
            fmt="html", hours=24, summary_rows=rows,
        )
        assert payload["kind"] == "report"
        assert len(payload["report"]["summary_rows"]) == 20
        assert len(payload["report"]["title"]) <= 200
        encoded = dump_payload(payload)
        assert len(encoded) <= 65536
        assert json.loads(encoded)["attachment"]["filename"] == "x.html"

    def test_dump_payload_survives_unserialisable_objects(self):
        class Weird:
            def __repr__(self):
                return "weird"

        encoded = dump_payload({"kind": "report", "obj": Weird()})
        assert json.loads(encoded)["kind"] == "report"


# ---------------------------------------------------------------------------
# Outbox report delivery
# ---------------------------------------------------------------------------
def _configure_email(manager, host, port, **overrides):
    cfg = {
        "host": host,
        "port": port,
        "user": "",
        "password": "",
        "from_addr": "alerts@example.com",
        "from_name": "NetGuard IDS",
        "to_addr": "soc@example.com",
        "use_tls": False,
        "tls_mode": "none",
    }
    cfg.update(overrides)
    ok, message = manager.configure_provider("email", cfg, persist=False)
    assert ok, message


def _outbox_row(conn, job_id):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, status, retry_count, error_message, next_retry_at "
        "FROM notification_outbox WHERE id = ?",
        (job_id,),
    )
    row = cur.fetchone()
    cur.close()
    return dict(row)


class TestOutboxReportDelivery:
    def _enqueue(self, manager, workdir, to="soc@example.com"):
        artifact = generate_artifact(_StubGenerator(), "daily", 24, "html")
        payload = build_report_payload(
            artifact, report_title="NetGuard Daily Report", report_type="daily",
            fmt="html", hours=24,
            summary_rows=[("Total alerts", "3"), ("Critical", "1")],
        )
        job_id = manager.enqueue_report_email(
            artifact,
            report_payload=payload,
            subject="NetGuard IDS daily report",
            text_body="Daily report attached.",
            html_body="<p>Daily report attached.</p>",
            to=to,
        )
        return job_id, artifact

    def test_report_email_is_delivered_with_attachment(self, workdir):
        manager = NotificationOutboxManager(conn=workdir["conn"])
        with FakeSmtpServer() as server:
            _configure_email(manager, server.host, server.port)
            job_id, artifact = self._enqueue(manager, workdir)

            row = _outbox_row(workdir["conn"], job_id)
            assert row["status"] == "pending"

            delivered = manager.process_pending_outbox(max_items=5)
            assert delivered == 1

            row = _outbox_row(workdir["conn"], job_id)
            assert row["status"] == "sent"

            assert len(server.messages) == 1
            captured = server.messages[0]
            assert captured.rcpt_to == ["soc@example.com"]
            raw = captured.data.decode("utf-8", "replace")
            decoded = _decoded_body(captured.data)
            assert "NetGuard Daily Report" in decoded
            assert "text/html" in raw
            assert artifact.filename in decoded + raw
            # The rich body is rendered from the stored payload.
            assert "Total alerts" in decoded

    def test_report_email_respects_cc_and_bcc(self, workdir):
        manager = NotificationOutboxManager(conn=workdir["conn"])
        with FakeSmtpServer() as server:
            _configure_email(manager, server.host, server.port)
            artifact = generate_artifact(_StubGenerator(), "daily", 24, "html")
            payload = build_report_payload(
                artifact, report_title="Daily", report_type="daily",
                fmt="html", hours=24,
            )
            manager.enqueue_report_email(
                artifact, report_payload=payload, subject="Daily",
                text_body="body", html_body="<p>body</p>",
                to="soc@example.com", cc="lead@example.com",
                bcc="audit@example.com",
            )
            assert manager.process_pending_outbox(max_items=5) == 1
            assert set(server.messages[0].rcpt_to) == {
                "soc@example.com", "lead@example.com", "audit@example.com",
            }
            raw = server.messages[0].data.decode("utf-8", "replace")
            assert "\nBcc:" not in raw

    def test_alert_email_uses_configured_cc_and_bcc_defaults(self, workdir):
        manager = NotificationOutboxManager(conn=workdir["conn"])
        with FakeSmtpServer() as server:
            _configure_email(
                manager, server.host, server.port,
                cc_addr="lead@example.com", bcc_addr="audit@example.com",
            )
            enqueued = manager.enqueue_alert(
                {
                    "severity": "high",
                    "rule_name": "PORT_SCAN",
                    "detail": "Multiple destination ports contacted.",
                    "src_ip": "192.0.2.10",
                    "dst_ip": "198.51.100.20",
                    "protocol": "TCP",
                },
                enabled_providers=["email"],
            )
            assert enqueued == 1

            cur = workdir["conn"].cursor()
            cur.execute(
                "SELECT id FROM notification_outbox WHERE rule_name = 'PORT_SCAN' ORDER BY id DESC LIMIT 1"
            )
            job_id = cur.fetchone()[0]
            cur.close()

            assert manager.process_pending_outbox(max_items=5) == 1
            assert _outbox_row(workdir["conn"], job_id)["status"] == "sent"
            assert set(server.messages[0].rcpt_to) == {
                "soc@example.com", "lead@example.com", "audit@example.com",
            }
            raw = server.messages[0].data.decode("utf-8", "replace")
            assert "Cc: lead@example.com" in raw
            assert "\nBcc:" not in raw
            assert "audit@example.com" not in raw

    def test_missing_attachment_still_sends_covering_email(self, workdir):
        manager = NotificationOutboxManager(conn=workdir["conn"])
        with FakeSmtpServer() as server:
            _configure_email(manager, server.host, server.port)
            job_id, artifact = self._enqueue(manager, workdir)
            os.unlink(artifact.path)

            assert manager.process_pending_outbox(max_items=5) == 1
            row = _outbox_row(workdir["conn"], job_id)
            assert row["status"] == "sent"
            raw = server.messages[0].data.decode("utf-8", "replace")
            # No MIME attachment part: the covering email is still delivered.
            assert "Content-Disposition: attachment" not in raw
            assert "NetGuard Daily Report" in _decoded_body(server.messages[0].data)

    def test_unconfigured_email_queues_without_sending(self, workdir):
        manager = NotificationOutboxManager(conn=workdir["conn"])
        artifact = generate_artifact(_StubGenerator(), "daily", 24, "html")
        payload = build_report_payload(
            artifact, report_title="Daily", report_type="daily",
            fmt="html", hours=24,
        )
        job_id = manager.enqueue_report_email(
            artifact, report_payload=payload, subject="Daily",
            text_body="body", html_body="<p>body</p>", to="soc@example.com",
        )
        assert _outbox_row(workdir["conn"], job_id)["status"] == "unconfigured"
        assert manager.process_pending_outbox(max_items=5) == 0

    def test_permanent_auth_failure_is_not_retried(self, workdir):
        manager = NotificationOutboxManager(conn=workdir["conn"])
        with FakeSmtpServer(require_auth=True,
                            username="ops@example.com",
                            password="right-password") as server:
            _configure_email(
                manager, server.host, server.port,
                user="ops@example.com", password="wrong-password",
            )
            job_id, _ = self._enqueue(manager, workdir)
            assert manager.process_pending_outbox(max_items=5) == 0

            row = _outbox_row(workdir["conn"], job_id)
            assert row["status"] == "failed"
            assert row["retry_count"] == 1
            assert row["error_message"].startswith("auth:")

    def test_transient_failure_is_scheduled_for_retry(self, workdir):
        manager = NotificationOutboxManager(conn=workdir["conn"])
        # Reserve then release a loopback port so the connection is refused.
        import socket

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        _configure_email(manager, "127.0.0.1", port)
        job_id, _ = self._enqueue(manager, workdir)
        before = time.time()
        assert manager.process_pending_outbox(max_items=5) == 0

        row = _outbox_row(workdir["conn"], job_id)
        assert row["status"] == "pending"
        assert row["retry_count"] == 1
        assert row["next_retry_at"] > before
        assert "transient" in (row["error_message"] or "")

    def test_claim_prevents_duplicate_delivery(self, workdir):
        manager = NotificationOutboxManager(conn=workdir["conn"])
        with FakeSmtpServer() as server:
            _configure_email(manager, server.host, server.port)
            job_id, _ = self._enqueue(manager, workdir)

            assert manager._claim_job(job_id) is True
            assert manager._claim_job(job_id) is False
            assert manager.process_pending_outbox(max_items=5) == 0
            assert server.messages == []

    def test_stale_claim_is_recovered(self, workdir):
        manager = NotificationOutboxManager(conn=workdir["conn"])
        with FakeSmtpServer() as server:
            _configure_email(manager, server.host, server.port)
            job_id, _ = self._enqueue(manager, workdir)
            assert manager._claim_job(job_id) is True

            # Simulate a worker that died while holding the claim.
            cur = workdir["conn"].cursor()
            cur.execute(
                "UPDATE notification_outbox SET next_retry_at = ? WHERE id = ?",
                (time.time() - 1000, job_id),
            )
            workdir["conn"].commit()
            cur.close()

            recovered = manager.recover_stale_claims(stale_after_s=300)
            assert recovered >= 1
            assert _outbox_row(workdir["conn"], job_id)["status"] == "pending"

            assert manager.process_pending_outbox(max_items=5) == 1
            assert len(server.messages) == 1
