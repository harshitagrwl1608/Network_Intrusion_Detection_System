"""
ids_project/tests/smtp_test_server.py
-------------------------------------
A minimal, dependency-free SMTP server used to exercise the NetGuard email
provider end-to-end without contacting a real mail relay.

It implements just enough of RFC 5321 for ``smtplib``:

* ``EHLO``/``HELO`` (advertises SIZE; STARTTLS is optional)
* ``AUTH LOGIN`` with configurable credentials
* ``MAIL FROM`` / ``RCPT TO`` (with configurable rejections)
* ``DATA`` with dot-unstuffing
* ``QUIT``

Nothing is written to disk; captured messages live in memory for assertions.
This is test-only code and must never be shipped in a deployment path.
"""

from __future__ import annotations

import base64
import socket
import threading
from dataclasses import dataclass, field


@dataclass
class CapturedMessage:
    mail_from: str = ""
    rcpt_to: list[str] = field(default_factory=list)
    data: bytes = b""
    authenticated: bool = False


class FakeSmtpServer:
    """Threaded single-connection-at-a-time fake SMTP server."""

    def __init__(self, *, require_auth: bool = False,
                 username: str = "smtp-user@example.com",
                 password: str = "correct-horse-battery",
                 reject_recipients: tuple[str, ...] = (),
                 advertise_starttls: bool = False,
                 delay_before_greeting: float = 0.0):
        self.require_auth = require_auth
        self.username = username
        self.password = password
        self.reject_recipients = {r.lower() for r in reject_recipients}
        self.advertise_starttls = advertise_starttls
        self.delay_before_greeting = delay_before_greeting

        self.messages: list[CapturedMessage] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.host, self.port = self._sock.getsockname()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- lifecycle ------------------------------------------------------

    def start(self) -> "FakeSmtpServer":
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=3)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False

    # -- protocol -------------------------------------------------------

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                self._handle(conn)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn: socket.socket) -> None:
        if self.delay_before_greeting:
            # Used to simulate an unresponsive server for timeout tests.
            if self._stop.wait(self.delay_before_greeting):
                return

        conn.settimeout(10)
        send = lambda text: conn.sendall((text + "\r\n").encode("utf-8"))
        send("220 fake.local ESMTP NetGuard test server")

        msg = CapturedMessage()
        authenticated = False
        while not self._stop.is_set():
            line = self._readline(conn)
            if line is None:
                return
            upper = line.upper()

            if upper.startswith("EHLO"):
                extensions = ["250-fake.local", "250-SIZE 10485760", "250-8BITMIME"]
                if not self.require_auth:
                    extensions.append("250-AUTH LOGIN PLAIN")
                else:
                    extensions.append("250-AUTH LOGIN PLAIN")
                if self.advertise_starttls:
                    extensions.append("250-STARTTLS")
                extensions.append("250 HELP")
                for item in extensions:
                    send(item)
            elif upper.startswith("HELO"):
                send("250 fake.local")
            elif upper.startswith("STARTTLS"):
                if self.advertise_starttls:
                    send("454 TLS not actually configured in the test server")
                else:
                    send("502 STARTTLS not implemented")
            elif upper.startswith("AUTH PLAIN"):
                token = line[len("AUTH PLAIN"):].strip()
                if not token:
                    send("334 ")
                    token = self._readline(conn) or ""
                try:
                    decoded = base64.b64decode(token).decode()
                except Exception:
                    send("501 Cannot decode credentials")
                    continue
                parts = decoded.split("\x00")
                user = parts[1] if len(parts) >= 3 else parts[0]
                pwd = parts[2] if len(parts) >= 3 else parts[1] if len(parts) == 2 else ""
                if user == self.username and pwd == self.password:
                    authenticated = True
                    msg.authenticated = True
                    send("235 2.7.0 Authentication successful")
                else:
                    send("535 5.7.8 Username and Password not accepted")
            elif upper.startswith("AUTH LOGIN"):
                send("334 VXNlcm5hbWU6")
                user_b64 = self._readline(conn)
                send("334 UGFzc3dvcmQ6")
                pass_b64 = self._readline(conn)
                if user_b64 is None or pass_b64 is None:
                    return
                try:
                    user = base64.b64decode(user_b64).decode()
                    pwd = base64.b64decode(pass_b64).decode()
                except Exception:
                    send("501 Cannot decode credentials")
                    continue
                if user == self.username and pwd == self.password:
                    authenticated = True
                    msg.authenticated = True
                    send("235 2.7.0 Authentication successful")
                else:
                    send("535 5.7.8 Username and Password not accepted")
            elif upper.startswith("MAIL FROM:"):
                msg.mail_from = self._address(line.split(":", 1)[1])
                if self.require_auth and not authenticated:
                    send("530 5.7.0 Authentication Required")
                else:
                    send("250 2.1.0 Ok")
            elif upper.startswith("RCPT TO:"):
                rcpt = self._address(line.split(":", 1)[1])
                if self.require_auth and not authenticated:
                    send("530 5.7.0 Authentication Required")
                elif rcpt.lower() in self.reject_recipients:
                    send(f"550 5.1.1 <{rcpt}>: Recipient address rejected")
                else:
                    msg.rcpt_to.append(rcpt)
                    send("250 2.1.5 Ok")
            elif upper == "DATA":
                send("354 End data with <CR><LF>.<CR><LF>")
                msg.data = self._read_data(conn)
                self.messages.append(msg)
                send("250 2.0.0 Ok: queued")
            elif upper == "RSET":
                msg = CapturedMessage()
                send("250 2.0.0 Ok")
            elif upper == "NOOP":
                send("250 2.0.0 Ok")
            elif upper == "QUIT":
                send("221 2.0.0 Bye")
                return
            else:
                send("502 5.5.2 Command not implemented")

    @staticmethod
    def _address(raw: str) -> str:
        """Extract the address from ``<addr> KEY=VALUE ...``."""
        raw = raw.strip()
        if "<" in raw and ">" in raw:
            return raw[raw.index("<") + 1: raw.index(">")].strip()
        return raw.split()[0].strip("<>") if raw else ""

    @staticmethod
    def _readline(conn: socket.socket) -> str | None:
        buf = b""
        while True:
            try:
                ch = conn.recv(1)
            except (socket.timeout, OSError):
                return None
            if not ch:
                return None
            if ch == b"\n":
                return buf.decode("utf-8", "replace").rstrip("\r")
            buf += ch

    def _read_data(self, conn: socket.socket) -> bytes:
        chunks: list[bytes] = []
        buf = b""
        while True:
            ch = conn.recv(1)
            if not ch:
                break
            buf += ch
            if buf.endswith(b"\r\n.\r\n"):
                chunks.append(buf[:-5])
                break
            if buf.endswith(b"\n.\n") and not buf.startswith(b".."):
                # Tolerate bare-LF clients.
                chunks.append(buf[:-3])
                break
        return b"".join(chunks)
