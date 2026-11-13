"""
tests/test_email_pipeline.py
----------------------------
Focused regression tests for the email notification pipeline.

Coverage:

1. Recipient parsing/validation (``notifications.email_utils``)
   - delimiter handling, de-duplication, header-injection rejection
   - per-field and global recipient ceilings
   - sender formatting and address redaction
2. SMTP provider behaviour (``notifications.providers.EmailProvider``)
   - no silent ``netguard-ids@localhost`` sender fallback (Gmail 530 root cause)
   - fail-closed authentication when a username has no stored password
   - STARTTLS refusal when the server does not advertise the extension
   - end-to-end delivery against an in-process fake SMTP server
   - To/Cc/Bcc envelope handling with Bcc kept out of visible headers
   - subject header-injection neutralisation
   - attachment size ceiling
   - permanent vs transient SMTP error classification

All servers are local fakes; no real SMTP credentials are used.
"""

from __future__ import annotations

import os
import smtplib
import socket
import sys
import tempfile
from unittest.mock import patch

import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)
if os.path.dirname(__file__) not in sys.path:
    sys.path.insert(0, os.path.dirname(__file__))

from notifications.email_utils import (  # noqa: E402
    MAX_RECIPIENTS_PER_FIELD,
    MAX_TOTAL_RECIPIENTS,
    RecipientError,
    format_sender,
    parse_all_recipients,
    parse_recipients,
    redact_address,
    split_recipient_string,
)
from notifications.providers import (  # noqa: E402
    EmailProvider,
    classify_smtp_error,
)
from smtp_test_server import FakeSmtpServer  # noqa: E402


SMTP_ENV_VARS = (
    "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD",
    "SMTP_FROM", "SMTP_FROM_NAME", "SMTP_TO", "SMTP_CC", "SMTP_BCC",
)


@pytest.fixture(autouse=True)
def _clean_smtp_env(monkeypatch):
    """Isolate every test from ambient SMTP configuration."""
    for var in SMTP_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# Recipient parsing
# ---------------------------------------------------------------------------
class TestRecipientParsing:
    def test_split_supports_semicolons_commas_and_newlines(self):
        raw = "a@example.com; b@example.com,\nc@example.com\n\n"
        assert split_recipient_string(raw) == [
            "a@example.com", "b@example.com", "c@example.com",
        ]

    def test_split_accepts_iterables(self):
        assert split_recipient_string(["a@example.com", "b@example.com"]) == [
            "a@example.com", "b@example.com",
        ]

    def test_parse_deduplicates_case_insensitively(self):
        valid, invalid = parse_recipients(
            "Ops@Example.com, ops@example.com, sec@example.com"
        )
        assert valid == ["Ops@Example.com", "sec@example.com"]
        assert invalid == []

    def test_display_name_is_unwrapped(self):
        valid, _ = parse_recipients('"Ops Team" <ops@example.com>')
        assert valid == ["ops@example.com"]

    def test_header_injection_is_rejected(self):
        # A CR/LF in an address would allow header injection. The injected line
        # is split off and fails validation, which blocks the whole send.
        injected = "attacker@example.com\r\nBcc: victim@example.com"
        valid, invalid = parse_recipients(injected)
        assert invalid, "injected header line must be reported as invalid"
        assert not any(v.lower() == "victim@example.com" for v in valid)

    def test_nul_byte_rejected(self):
        valid, invalid = parse_recipients("a@example.com\x00")
        assert valid == []
        assert invalid

    def test_unicode_line_separator_splits_rather_than_injects(self):
        valid, invalid = parse_recipients("a@example.com\u2028b@example.com")
        assert valid == ["a@example.com", "b@example.com"]
        assert invalid == []

    @pytest.mark.parametrize("bad", [
        "no-at-sign",
        "two@@example.com",
        "user@localhost",
        "@example.com",
        "user@",
        "user@example",
        "user@-example.com",
        "user@example..com",
    ])
    def test_syntactically_invalid_addresses_rejected(self, bad):
        valid, invalid = parse_recipients(bad)
        assert valid == []
        assert invalid == [bad]

    def test_oversized_address_rejected(self):
        local = "a" * 250
        valid, invalid = parse_recipients(f"{local}@example.com")
        assert valid == []
        assert invalid

    def test_per_field_ceiling_truncates_and_reports(self):
        raw = ", ".join(f"user{i}@example.com" for i in range(MAX_RECIPIENTS_PER_FIELD + 3))
        valid, invalid = parse_recipients(raw)
        assert len(valid) == MAX_RECIPIENTS_PER_FIELD
        assert len(invalid) == 3

    def test_global_ceiling_produces_blocking_error(self):
        to_raw = ", ".join(f"to{i}@example.com" for i in range(MAX_RECIPIENTS_PER_FIELD))
        cc_raw = ", ".join(f"cc{i}@example.com" for i in range(MAX_RECIPIENTS_PER_FIELD))
        bcc_raw = ", ".join(f"bcc{i}@example.com" for i in range(MAX_RECIPIENTS_PER_FIELD))
        parsed = parse_all_recipients(to_raw, cc_raw, bcc_raw)
        assert parsed["errors"], "expected a blocking recipient-count error"
        assert any("Too many recipients" in e for e in parsed["errors"])

    def test_missing_to_is_a_blocking_error(self):
        parsed = parse_all_recipients("", "cc@example.com")
        assert parsed["to"] == []
        assert any("'To' recipient" in e for e in parsed["errors"])

    def test_invalid_entries_are_attributed_to_their_field(self):
        parsed = parse_all_recipients("ok@example.com", "bad-entry", "also bad")
        fields = {item["field"] for item in parsed["invalid"]}
        assert fields == {"cc", "bcc"}


class TestSenderFormatting:
    def test_display_name_is_applied(self):
        rendered = format_sender("ops@example.com", "NetGuard IDS")
        assert rendered == "NetGuard IDS <ops@example.com>"

    def test_control_characters_are_stripped_from_display_name(self):
        rendered = format_sender("ops@example.com", "Evil\r\nBcc: victim@example.com")
        assert "\r" not in rendered and "\n" not in rendered
        assert rendered.endswith("<ops@example.com>")

    def test_sender_control_characters_raise(self):
        with pytest.raises(RecipientError):
            format_sender("ops@example.com\nBcc: victim@example.com", "x")

    def test_redaction_masks_local_part(self):
        assert redact_address("someone@example.com") == "som***@example.com"
        assert redact_address("ab@example.com") == "a***@example.com"
        assert redact_address("not-an-address") == "***"


# ---------------------------------------------------------------------------
# Provider configuration
# ---------------------------------------------------------------------------
class TestProviderConfiguration:
    def test_no_localhost_sender_fallback(self):
        """Regression: the old provider defaulted to netguard-ids@localhost."""
        provider = EmailProvider(host="smtp.example.com")
        assert provider.from_addr == ""
        assert provider.is_configured is False

    def test_username_without_password_fails_closed(self):
        provider = EmailProvider(
            host="smtp.example.com", user="ops@example.com", password="",
            from_addr="ops@example.com", to_addr="soc@example.com",
        )
        assert provider.auth_required_but_missing is True
        ok, message = provider.send()
        assert ok is False
        assert "no password is stored" in message
        # Nothing was transmitted, so no classified error is recorded.
        assert provider.last_detail.get("error_class") is None

    def test_unconfigured_provider_reports_configuration_error(self):
        ok, message = EmailProvider(host="", from_addr="").send()
        assert ok is False
        assert "not configured" in message

    def test_tls_defaults_follow_port(self):
        assert EmailProvider(host="h", from_addr="a@example.com", port=465).tls_mode == "ssl"
        assert EmailProvider(host="h", from_addr="a@example.com", port=587).tls_mode == "starttls"
        assert EmailProvider(
            host="h", from_addr="a@example.com", port=25, use_tls=False
        ).tls_mode == "none"

    def test_describe_never_leaks_the_password(self):
        provider = EmailProvider(
            host="smtp.example.com", user="ops@example.com",
            password="super-secret", from_addr="ops@example.com",
            to_addr="soc@example.com", cc_addr="cc@example.com",
        )
        described = provider.describe()
        assert "super-secret" not in str(described)
        assert described["authenticated"] is True
        assert described["username"] == "o***@example.com"
        assert described["cc_configured"] is True


# ---------------------------------------------------------------------------
# Delivery against a local fake SMTP server
# ---------------------------------------------------------------------------
class TestSmtpDelivery:
    def _provider(self, server, **overrides):
        config = dict(
            host=server.host, port=server.port,
            from_addr="alerts@example.com",
            from_name="NetGuard IDS",
            to_addr="soc@example.com",
            tls_mode="none",
            timeout=5.0,
        )
        config.update(overrides)
        return EmailProvider(**config)

    def test_end_to_end_delivery_with_cc_and_bcc(self):
        with FakeSmtpServer() as server:
            provider = self._provider(
                server, cc_addr="lead@example.com", bcc_addr="audit@example.com",
            )
            ok, message = provider.send(
                subject="High severity alert",
                body="An alert fired.",
                html_body="<p>An alert fired.</p>",
            )
            assert ok is True, message
            assert len(server.messages) == 1

            captured = server.messages[0]
            assert captured.mail_from == "alerts@example.com"
            assert set(captured.rcpt_to) == {
                "soc@example.com", "lead@example.com", "audit@example.com",
            }

            raw = captured.data.decode("utf-8", "replace")
            assert "Subject: High severity alert" in raw
            assert "Cc: lead@example.com" in raw
            # Bcc must never appear as a visible header.
            assert "\nBcc:" not in raw
            assert "audit@example.com" not in raw

    def test_authenticated_delivery(self):
        with FakeSmtpServer(require_auth=True,
                            username="ops@example.com",
                            password="app-password") as server:
            provider = self._provider(
                server, user="ops@example.com", password="app-password",
            )
            ok, message = provider.send(subject="auth", body="body")
            assert ok is True, message
            assert server.messages[0].authenticated is True

    def test_authentication_failure_is_permanent(self):
        with FakeSmtpServer(require_auth=True,
                            username="ops@example.com",
                            password="right-password") as server:
            provider = self._provider(
                server, user="ops@example.com", password="wrong-password",
            )
            ok, message = provider.send(subject="auth", body="body")
            assert ok is False
            assert "authentication failed" in message.lower()
            assert provider.last_detail["transient"] is False
            assert provider.last_detail["error_class"] == "auth"

    def test_starttls_refused_when_not_advertised(self):
        with FakeSmtpServer(advertise_starttls=False) as server:
            provider = self._provider(server, tls_mode="starttls")
            ok, message = provider.send(subject="s", body="b")
            assert ok is False
            assert "STARTTLS" in message
            # Credentials must never be sent over a cleartext channel.
            assert server.messages == []

    def test_subject_header_injection_is_neutralised(self):
        with FakeSmtpServer() as server:
            provider = self._provider(server)
            ok, message = provider.send(
                subject="Alert\r\nBcc: attacker@example.com", body="body",
            )
            assert ok is True, message
            raw = server.messages[0].data.decode("utf-8", "replace")
            headers = raw.split("\r\n\r\n", 1)[0]
            # No additional header may be created by the injected text.
            assert not any(
                line.lower().startswith("bcc:")
                for line in headers.replace("\r\n", "\n").split("\n")
            )

    def test_partial_recipient_rejection(self):
        with FakeSmtpServer(reject_recipients=("blocked@example.com",)) as server:
            provider = self._provider(server, cc_addr="blocked@example.com")
            ok, message = provider.send(subject="s", body="b")
            assert ok is True
            assert "1 of 2" in message
            assert provider.last_detail.get("partial") is True
            assert provider.last_detail["recipients_rejected"] == ["blocked@example.com"]

    def test_all_recipients_rejected(self):
        with FakeSmtpServer(
            reject_recipients=("soc@example.com", "blocked@example.com"),
        ) as server:
            provider = self._provider(server, cc_addr="blocked@example.com")
            ok, message = provider.send(subject="s", body="b")
            assert ok is False
            assert "All 2 recipients" in message

    def test_invalid_recipient_blocks_send_without_connecting(self):
        with FakeSmtpServer() as server:
            provider = self._provider(server)
            ok, message = provider.send(
                recipient="not-an-address, soc@example.com", subject="s", body="b",
            )
            assert ok is False
            assert "rejected as invalid" in message
            assert server.messages == []

    def test_attachment_is_delivered_as_base64_part(self):
        with FakeSmtpServer() as server:
            provider = self._provider(server)
            ok, message = provider.send(
                subject="report", body="see attached",
                attachments=[{
                    "filename": "report.csv",
                    "mime": "text/csv",
                    "data": b"a,b\n1,2\n",
                }],
            )
            assert ok is True, message
            raw = server.messages[0].data.decode("utf-8", "replace")
            assert 'filename="report.csv"' in raw
            assert "Content-Type: text/csv" in raw

    def test_attachment_size_ceiling_is_enforced(self):
        with FakeSmtpServer() as server:
            provider = self._provider(server)
            with patch("notifications.providers.MAX_ATTACHMENT_BYTES", 16):
                ok, message = provider.send(
                    subject="report", body="x",
                    attachments=[{
                        "filename": "big.bin",
                        "mime": "application/octet-stream",
                        "data": b"x" * 64,
                    }],
                )
            assert ok is False
            assert "exceeds" in message
            assert server.messages == []

    def test_missing_attachment_path_is_reported(self):
        with FakeSmtpServer() as server:
            provider = self._provider(server)
            missing = os.path.join(tempfile.mkdtemp(), "gone.csv")
            ok, message = provider.send(
                subject="report", body="x",
                attachments=[{"filename": "gone.csv", "path": missing}],
            )
            assert ok is False
            assert "missing" in message

    def test_attachment_filename_cannot_escape(self):
        with FakeSmtpServer() as server:
            provider = self._provider(server)
            ok, message = provider.send(
                subject="report", body="x",
                attachments=[{
                    "filename": "../../etc/passwd",
                    "mime": "text/plain",
                    "data": b"x",
                }],
            )
            assert ok is True, message
            raw = server.messages[0].data.decode("utf-8", "replace")
            assert "passwd" in raw  # basename retained
            assert ".." not in raw.split("filename=")[1][:40]

    def test_connection_refused_is_transient(self):
        # Port 1 on loopback is reliably closed.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        provider = EmailProvider(
            host="127.0.0.1", port=port, from_addr="alerts@example.com",
            to_addr="soc@example.com", tls_mode="none", timeout=2.0,
        )
        ok, message = provider.send(subject="s", body="b")
        assert ok is False
        assert provider.last_detail["transient"] is True


class TestSmtpErrorClassification:
    def test_authentication_error(self):
        exc = smtplib.SMTPAuthenticationError(535, b"bad credentials")
        assert classify_smtp_error(exc) == "auth"

    def test_auth_response_code_without_auth_exception(self):
        exc = smtplib.SMTPResponseException(530, b"Authentication Required")
        assert classify_smtp_error(exc) == "auth"

    def test_transient_response_code(self):
        exc = smtplib.SMTPResponseException(451, b"try later")
        assert classify_smtp_error(exc) == "transient"

    def test_permanent_response_code(self):
        exc = smtplib.SMTPResponseException(550, b"no such user")
        assert classify_smtp_error(exc) == "permanent"

    def test_recipients_refused_is_permanent(self):
        exc = smtplib.SMTPRecipientsRefused({"a@example.com": (550, b"no")})
        assert classify_smtp_error(exc) == "permanent"

    def test_sender_refused_is_permanent(self):
        exc = smtplib.SMTPSenderRefused(553, b"bad sender", "a@example.com")
        assert classify_smtp_error(exc) == "permanent"

    def test_disconnect_and_timeout_are_transient(self):
        assert classify_smtp_error(smtplib.SMTPServerDisconnected("gone")) == "transient"
        assert classify_smtp_error(TimeoutError("slow")) == "transient"
        assert classify_smtp_error(ConnectionRefusedError()) == "transient"
