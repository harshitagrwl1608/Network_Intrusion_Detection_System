"""
notifications/providers.py
--------------------------
Notification provider adapters for SMTP Email, Telegram Bot, HTTP Webhooks,
Twilio SMS, and Browser Push.

The SMTP adapter is the only one with an extended contract; it supports
multi-recipient delivery (To/Cc/Bcc), multipart HTML + plain-text bodies,
attachments, explicit TLS modes, and fail-closed authentication.
"""

import os
import sys
import json
import hmac
import hashlib
import smtplib
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formatdate, make_msgid
import logging
from typing import Any, Iterable

from notifications.email_utils import (
    RecipientError,
    format_sender,
    parse_all_recipients,
    parse_recipients,
    redact_address,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SMTP error classification
# ---------------------------------------------------------------------------
# Transient errors are worth retrying with backoff; permanent errors are not.
TRANSIENT_SMTP_CODES = {421, 450, 451, 452}
PERMANENT_SMTP_CODES = {500, 501, 502, 503, 504, 521, 530, 535, 538, 540,
                        550, 551, 552, 553, 554, 556}
AUTH_SMTP_CODES = {530, 535, 538}

# Hard cap on a single attachment so a report job cannot exhaust memory.
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024


def classify_smtp_error(exc: BaseException) -> str:
    """Classify an SMTP failure as ``auth``, ``permanent``, or ``transient``."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "auth"
    if isinstance(exc, (smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused)):
        return "permanent"
    if isinstance(exc, smtplib.SMTPDataError):
        code = int(getattr(exc, "smtp_code", 0) or 0)
        return "transient" if code in TRANSIENT_SMTP_CODES else "permanent"
    if isinstance(exc, smtplib.SMTPResponseException):
        code = int(getattr(exc, "smtp_code", 0) or 0)
        if code in AUTH_SMTP_CODES:
            return "auth"
        if code in TRANSIENT_SMTP_CODES:
            return "transient"
        return "permanent"
    if isinstance(exc, (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError,
                        smtplib.SMTPHeloError, socket.timeout,
                        TimeoutError, ConnectionError, OSError, ssl.SSLError)):
        return "transient"
    return "transient"


def _sanitize_error_text(text: str) -> str:
    """Flatten and bound an error string destined for logs or the database."""
    flat = " ".join(str(text or "").split())
    return flat[:500]


class EmailProvider:
    """Delivers security incident notifications via SMTP email.

    Notable behaviours:

    * ``from_addr`` has **no** silent fallback. An unconfigured provider
      previously defaulted to ``netguard-ids@localhost``, which produced an
      unexpected sender and caused ``530 Authentication Required`` responses
      from relays such as Gmail.
    * When a username is configured but no password is present, delivery fails
      closed with an explicit diagnostic instead of attempting an
      unauthenticated transaction.
    * ``use_tls=True`` negotiates STARTTLS (ports 587/25). Port 465 uses implicit
      TLS. ``tls_mode`` may be set explicitly to ``starttls``, ``ssl`` or
      ``none``.
    """

    def __init__(self, host: str = "", port: int = 587,
                 user: str = "", password: str = "",
                 from_addr: str = "", to_addr: str = "", use_tls: bool = True,
                 from_name: str = "", cc_addr: str = "", bcc_addr: str = "",
                 tls_mode: str | None = None, timeout: float = 10.0,
                 allow_unauthenticated: bool | None = None):
        self.host = host or os.getenv("SMTP_HOST", "")
        try:
            self.port = int(port or os.getenv("SMTP_PORT", 587))
        except (TypeError, ValueError):
            self.port = 587
        self.user = user or os.getenv("SMTP_USER", "")
        self.password = password or os.getenv("SMTP_PASSWORD", "")
        # No localhost fallback: an empty sender must surface as a configuration
        # error rather than masquerade as a valid address.
        self.from_addr = from_addr or os.getenv("SMTP_FROM", "")
        self.from_name = from_name or os.getenv("SMTP_FROM_NAME", "NetGuard IDS")
        self.to_addr = to_addr or os.getenv("SMTP_TO", "")
        self.cc_addr = cc_addr or os.getenv("SMTP_CC", "")
        self.bcc_addr = bcc_addr or os.getenv("SMTP_BCC", "")
        # `recipient` is retained for backwards compatibility with callers and
        # tests that read or assign it directly.
        self.recipient = self.to_addr
        self.use_tls = use_tls
        self.timeout = timeout
        self.allow_unauthenticated = allow_unauthenticated
        self.tls_mode = (tls_mode or "").lower().strip() or self._default_tls_mode()
        self.last_detail: dict[str, Any] = {}

    # -- configuration ---------------------------------------------------

    def _default_tls_mode(self) -> str:
        if self.port == 465:
            return "ssl"
        return "starttls" if self.use_tls else "none"

    @property
    def auth_required_but_missing(self) -> bool:
        """True when a username is set but the password is absent."""
        return bool(self.user) and not bool(self.password)

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.from_addr)

    @property
    def has_recipient(self) -> bool:
        try:
            valid, _ = parse_recipients(self.recipient or self.to_addr, "to")
        except Exception:
            return False
        return bool(valid)

    def describe(self) -> dict[str, Any]:
        """Return a secret-free description of the transport configuration."""
        return {
            "host": self.host,
            "port": self.port,
            "tls_mode": self.tls_mode,
            "authenticated": bool(self.user and self.password),
            "username": redact_address(self.user) if self.user else "",
            "from_addr": self.from_addr,
            "from_name": self.from_name,
            "cc_configured": bool(self.cc_addr),
            "bcc_configured": bool(self.bcc_addr),
        }

    # -- delivery --------------------------------------------------------

    def send(self, recipient: str | None = None, subject: str = "", body: str = "",
             alert_data: dict | None = None, *, html_body: str | None = None,
             cc: str | Iterable[str] | None = None,
             bcc: str | Iterable[str] | None = None,
             attachments: list[dict] | None = None) -> tuple[bool, str]:
        """Deliver one email.

        Returns ``(success, message)`` for backwards compatibility and stores
        richer diagnostics in :attr:`last_detail`.
        """
        self.last_detail = {
            "transient": False,
            "recipients_accepted": [],
            "recipients_rejected": [],
        }

        if not self.is_configured:
            return False, "SMTP server host or from-address not configured"

        # --- resolve recipients ----------------------------------------
        target = recipient if recipient is not None else self.recipient
        parsed = parse_all_recipients(
            target,
            cc if cc is not None else self.cc_addr,
            bcc if bcc is not None else self.bcc_addr,
        )
        if parsed["errors"]:
            self.last_detail["recipients_rejected"] = [e["value"] for e in parsed["invalid"]]
            return False, f"Recipient configuration invalid: {parsed['errors'][0]}"
        if parsed["invalid"]:
            rejected = [e["value"] for e in parsed["invalid"]]
            self.last_detail["recipients_rejected"] = rejected
            # Invalid addresses are a hard error: silently dropping them could
            # hide a typo in an intended recipient.
            return False, (
                f"{len(rejected)} recipient address(es) rejected as invalid; "
                "no message was sent"
            )

        to_list = parsed["to"]
        cc_list = parsed["cc"]
        bcc_list = parsed["bcc"]
        envelope = to_list + cc_list + bcc_list
        self.last_detail["recipients_accepted"] = list(envelope)

        # --- authentication policy -------------------------------------
        if self.auth_required_but_missing:
            return False, (
                f"SMTP authentication required by {self.host or 'server'}: "
                "a username is configured but no password is stored. "
                "Set the SMTP password in Notification settings."
            )
        if not self.user and self.allow_unauthenticated is False:
            return False, "SMTP authentication required but no username is configured"

        # --- build message ---------------------------------------------
        try:
            sender_header = format_sender(self.from_addr, self.from_name)
        except RecipientError as exc:
            return False, f"Invalid sender address: {exc}"

        try:
            msg = MIMEMultipart("mixed")
            msg["Subject"] = str(subject or "NetGuard IDS notification").replace("\r", " ").replace("\n", " ")
            msg["From"] = sender_header
            msg["To"] = ", ".join(to_list)
            if cc_list:
                msg["Cc"] = ", ".join(cc_list)
            # Bcc is deliberately never written to a visible header.
            msg["Date"] = formatdate(localtime=True)
            msg["Message-ID"] = make_msgid(idstring="netguard-ids")
            msg["X-NetGuard-Sender"] = "NetGuard IDS"

            alternative = MIMEMultipart("alternative")
            alternative.attach(MIMEText(str(body or ""), "plain", "utf-8"))
            if html_body:
                alternative.attach(MIMEText(str(html_body), "html", "utf-8"))
            msg.attach(alternative)

            for att in attachments or []:
                loaded = self._load_attachment(att)
                if isinstance(loaded, tuple) and loaded[0] is None:
                    return False, loaded[1]
                data, filename, mime = loaded
                subtype = mime.split("/", 1)[-1] if "/" in mime else "octet-stream"
                part = MIMEApplication(data, _subtype=subtype)
                part.add_header("Content-Disposition", "attachment", filename=filename)
                if mime and "/" in mime:
                    try:
                        part.replace_header("Content-Type", f'{mime}; name="{filename}"')
                    except KeyError:
                        pass
                msg.attach(part)

            raw = msg.as_string()
        except Exception as exc:
            return False, f"Failed to build email message: {_sanitize_error_text(exc)}"

        # --- transmit ---------------------------------------------------
        server = None
        try:
            context = ssl.create_default_context()
            if self.tls_mode == "ssl":
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout,
                                          context=context)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
                server.ehlo()
                if self.tls_mode == "starttls":
                    if not server.has_extn("starttls"):
                        return False, (
                            f"SMTP server {self.host}:{self.port} does not advertise "
                            "STARTTLS; refusing to send credentials in the clear"
                        )
                    server.starttls(context=context)
                    server.ehlo()

            if self.user and self.password:
                server.login(self.user, self.password)

            refused: dict = {}
            try:
                # smtplib returns a dict of refused recipients when only some
                # were rejected; it raises only when *all* were. Both paths must
                # be surfaced so a silently-dropped recipient is impossible.
                refused = dict(server.sendmail(self.from_addr, envelope, raw) or {})
            except smtplib.SMTPRecipientsRefused as exc:
                refused = dict(getattr(exc, "recipients", {}) or {})
                if not refused:
                    raise

            try:
                server.quit()
            except Exception:
                pass
            server = None

            if refused:
                refused_keys = {str(k).lower() for k in refused}
                rejected = [a for a in envelope if a.lower() in refused_keys] or list(refused)
                accepted = [a for a in envelope if a.lower() not in refused_keys]
                self.last_detail["recipients_rejected"] = rejected
                self.last_detail["recipients_accepted"] = accepted
                if not accepted:
                    return False, (
                        f"All {len(rejected)} recipients were rejected by the SMTP server"
                    )
                self.last_detail["partial"] = True
                return True, (
                    f"Delivered to {len(accepted)} of {len(envelope)} recipients; "
                    f"{len(rejected)} rejected by server"
                )

            if len(envelope) > 1:
                return True, f"Delivered via SMTP to {len(envelope)} recipients"
            return True, "Delivered via SMTP"

        except smtplib.SMTPAuthenticationError as exc:
            self.last_detail["error_class"] = "auth"
            self.last_detail["transient"] = False
            return False, (
                f"SMTP authentication failed ({exc.smtp_code}). "
                "Verify the username and app-specific password."
            )
        except Exception as exc:
            error_class = classify_smtp_error(exc)
            self.last_detail["error_class"] = error_class
            self.last_detail["transient"] = error_class == "transient"
            detail = _sanitize_error_text(exc)
            return False, f"SMTP error ({error_class}): {detail}"
        finally:
            if server is not None:
                try:
                    server.close()
                except Exception:
                    pass

    # -- attachment loading ---------------------------------------------

    def _load_attachment(self, att: dict) -> tuple[bytes | None, str, str]:
        """Load one attachment descriptor into ``(bytes, filename, mime)``.

        Descriptors accept either in-memory ``data`` or a ``path``. Paths are
        validated by the caller (see ``notifications.report_delivery``) and the
        size is capped here as a second line of defence.
        On failure the bytes element is ``None`` and the second element is an
        error message.
        """
        if not isinstance(att, dict):
            return None, "Invalid attachment descriptor", ""

        filename = str(att.get("filename") or "attachment.bin")
        # Neutralise directory components and header-breaking characters.
        filename = os.path.basename(filename.replace("\\", "/"))
        filename = "".join(ch for ch in filename if ch not in "\r\n\x00").strip()
        if not filename:
            return None, "Attachment filename is empty", ""
        if len(filename) > 200:
            return None, "Attachment filename is too long", ""

        mime = str(att.get("mime") or "application/octet-stream")

        data = att.get("data")
        if data is None and att.get("path"):
            path = str(att["path"])
            try:
                if not os.path.isfile(path):
                    return None, "Attachment file is missing", ""
                if os.path.getsize(path) > MAX_ATTACHMENT_BYTES:
                    return None, (
                        f"Attachment exceeds the {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MiB limit"
                    ), ""
                with open(path, "rb") as handle:
                    data = handle.read(MAX_ATTACHMENT_BYTES + 1)
            except OSError as exc:
                return None, f"Unable to read attachment: {_sanitize_error_text(exc)}", ""

        if data is None:
            return None, "Attachment has no data", ""
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, (bytes, bytearray)):
            return None, "Attachment data must be bytes", ""
        data = bytes(data)
        if len(data) > MAX_ATTACHMENT_BYTES:
            return None, (
                f"Attachment exceeds the {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MiB limit"
            ), ""
        return data, filename, mime


class TelegramProvider:
    """Delivers alerts to a Telegram chat/channel via Bot API."""

    def __init__(self, bot_token: str = "", chat_id: str = ""):
        self.bot_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID", "")
        self.recipient = self.chat_id

    @property
    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    @property
    def has_recipient(self) -> bool:
        return bool(self.chat_id)

    def send(self, recipient: str | None = None, subject: str = "", body: str = "", alert_data: dict | None = None) -> tuple[bool, str]:
        if not self.is_configured:
            return False, "Telegram Bot Token or Chat ID not configured"

        target_chat = recipient or self.chat_id
        if not target_chat:
            return False, "Telegram recipient chat ID missing"
        text = f"🚨 *NetGuard IDS Alert*\n*{subject}*\n\n{body}"

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = json.dumps({
            "chat_id": target_chat,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }).encode("utf-8")

        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
                if data.get("ok"):
                    return True, "Delivered to Telegram"
                return False, f"Telegram API error: {data.get('description')}"
        except Exception as exc:
            return False, f"Telegram HTTP error: {exc}"


class WebhookProvider:
    """Delivers structured JSON alert payloads to generic HTTP webhooks with HMAC signatures."""

    def __init__(self, url: str = "", secret: str = ""):
        self.url = url or os.getenv("WEBHOOK_URL", "")
        self.secret = secret or os.getenv("WEBHOOK_SECRET", "")
        self.recipient = self.url

    @property
    def is_configured(self) -> bool:
        return bool(self.url and self.url.startswith(("http://", "https://")))

    @property
    def has_recipient(self) -> bool:
        return self.is_configured

    def send(self, recipient: str | None = None, subject: str = "", body: str = "", alert_data: dict | None = None) -> tuple[bool, str]:
        target_url = recipient or self.url
        if not target_url or not target_url.startswith(("http://", "https://")):
            return False, "Webhook endpoint URL not configured"

        payload_dict = {
            "source": "NetGuard IDS",
            "subject": subject,
            "message": body,
            "alert": alert_data or {},
            "timestamp": alert_data.get("timestamp") if alert_data else None,
        }
        raw_body = json.dumps(payload_dict, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "NetGuard-Webhook/1.0"}

        if self.secret:
            sig = hmac.new(self.secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
            headers["X-NetGuard-Signature"] = f"sha256={sig}"

        req = urllib.request.Request(target_url, data=raw_body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                code = resp.getcode()
                if 200 <= code < 300:
                    return True, f"Webhook accepted (HTTP {code})"
                return False, f"Webhook rejected (HTTP {code})"
        except urllib.error.HTTPError as exc:
            return False, f"Webhook HTTP error: {exc.code} {exc.reason}"
        except Exception as exc:
            return False, f"Webhook network error: {exc}"


class SmsProvider:
    """Optional SMS provider integration via Twilio REST API."""

    def __init__(self, account_sid: str = "", auth_token: str = "", from_number: str = "", to_number: str = ""):
        self.account_sid = account_sid or os.getenv("TWILIO_ACCOUNT_SID", "")
        self.auth_token = auth_token or os.getenv("TWILIO_AUTH_TOKEN", "")
        self.from_number = from_number or os.getenv("TWILIO_FROM_NUMBER", "")
        self.to_number = to_number or os.getenv("TWILIO_TO", "")
        self.recipient = self.to_number

    @property
    def is_configured(self) -> bool:
        return bool(self.account_sid and self.auth_token and self.from_number)

    @property
    def has_recipient(self) -> bool:
        return bool(self.recipient)

    def send(self, recipient: str | None = None, subject: str = "", body: str = "", alert_data: dict | None = None) -> tuple[bool, str]:
        if not self.is_configured:
            return False, "Twilio SMS provider credentials not configured (optional integration)"
        target_number = recipient or self.recipient
        if not target_number:
            return False, "Recipient phone number missing"

        url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"
        sms_text = f"[NetGuard] {subject}: {body}"[:160]  # Standard SMS segment limit
        data = urllib.parse.urlencode({
            "To": target_number,
            "From": self.from_number,
            "Body": sms_text,
        }).encode("utf-8")

        import base64
        creds = base64.b64encode(f"{self.account_sid}:{self.auth_token}".encode("utf-8")).decode("ascii")
        headers = {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                code = resp.getcode()
                if 200 <= code < 300:
                    return True, "SMS queued via Twilio"
                return False, f"Twilio returned HTTP {code}"
        except Exception as exc:
            return False, f"Twilio SMS error: {exc}"
