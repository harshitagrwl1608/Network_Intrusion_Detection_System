"""
notifications/providers.py
--------------------------
Notification provider adapters for SMTP Email, Telegram Bot, HTTP Webhooks,
Twilio SMS, and Browser Push.
"""

import os
import sys
import json
import hmac
import hashlib
import smtplib
import urllib.request
import urllib.error
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import Any

logger = logging.getLogger(__name__)


class EmailProvider:
    """Delivers security incident notifications via SMTP email."""

    def __init__(self, host: str = "", port: int = 587,
                 user: str = "", password: str = "",
                 from_addr: str = "", to_addr: str = "", use_tls: bool = True):
        self.host = host or os.getenv("SMTP_HOST", "")
        self.port = int(port or os.getenv("SMTP_PORT", 587))
        self.user = user or os.getenv("SMTP_USER", "")
        self.password = password or os.getenv("SMTP_PASSWORD", "")
        self.from_addr = from_addr or os.getenv("SMTP_FROM", "netguard-ids@localhost")
        self.to_addr = to_addr or os.getenv("SMTP_TO", "")
        self.recipient = self.to_addr
        self.use_tls = use_tls

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.from_addr)

    @property
    def has_recipient(self) -> bool:
        return bool(self.recipient and "@" in self.recipient)

    def send(self, recipient: str | None = None, subject: str = "", body: str = "", alert_data: dict | None = None) -> tuple[bool, str]:
        if not self.is_configured:
            return False, "SMTP server host or from-address not configured"
        target = recipient or self.recipient
        if not target:
            return False, "Recipient email address missing"

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[NetGuard IDS] {subject}"
            msg["From"] = self.from_addr
            msg["To"] = target

            text_part = MIMEText(body, "plain", "utf-8")
            msg.attach(text_part)

            server = smtplib.SMTP(self.host, self.port, timeout=10)
            if self.use_tls:
                server.starttls()
            if self.user and self.password:
                server.login(self.user, self.password)
            server.sendmail(self.from_addr, [target], msg.as_string())
            server.quit()
            return True, "Delivered via SMTP"
        except Exception as exc:
            return False, f"SMTP error: {exc}"


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
