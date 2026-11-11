"""
notifications/outbox.py
-----------------------
Asynchronous notification outbox with rate-limiting, deduplication,
exponential backoff retries, and provider routing.
"""

import time
import json
import logging
import threading
from typing import Any

from notifications.providers import (
    EmailProvider, TelegramProvider, WebhookProvider, SmsProvider
)

logger = logging.getLogger(__name__)


class NotificationOutboxManager:
    """
    Manages non-blocking outbox enqueueing and asynchronous background delivery.
    """

    def __init__(self, conn=None, min_severity: str = "high",
                 cooldown_s: float = 300.0, max_retries: int = 3,
                 main_conn=None, cooldown_seconds=None):
        self._conn = conn if conn is not None else main_conn
        self._min_severity = min_severity.lower()
        self._cooldown_s = cooldown_seconds if cooldown_seconds is not None else cooldown_s
        self._max_retries = max_retries

        self._providers = {
            "email": EmailProvider(),
            "telegram": TelegramProvider(),
            "webhook": WebhookProvider(),
            "sms": SmsProvider(),
        }

        # Cooldown cache: (rule_name, dst_ip) -> last_notification_time
        self._cooldown_cache: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None

    def set_connection(self, conn):
        with self._lock:
            self._conn = conn

    def get_provider(self, name: str):
        return self._providers.get(name.lower())

    def get_providers_status(self) -> dict[str, dict[str, Any]]:
        """Return configuration and health status of all notification providers."""
        res = {}
        for name, p in self._providers.items():
            res[name] = {
                "name": name,
                "configured": getattr(p, "is_configured", False),
            }
        return res

    def enqueue_alert(self, alert: dict, alert_id: int | None = None,
                      enabled_providers: list[str] | None = None) -> int:
        """
        Evaluate alert severity and cooldown, then enqueue to outbox table.
        Returns number of notification jobs enqueued.
        """
        sev = (alert.get("severity") or "medium").lower()
        sev_ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = sev_ranks.get(self._min_severity, 3)
        if sev_ranks.get(sev, 2) < min_rank:
            return 0  # Below notification threshold

        rule_name = str(alert.get("rule_name") or "ALERT")
        dst_ip = str(alert.get("dst_ip") or "")
        key = (rule_name, dst_ip)

        now = time.time()
        with self._lock:
            last_sent = self._cooldown_cache.get(key, 0.0)
            if now - last_sent < self._cooldown_s:
                logger.debug(f"Notification suppressed by cooldown for {key}")
                return 0
            self._cooldown_cache[key] = now

        if not self._conn:
            return 0

        providers = enabled_providers or ["webhook", "email", "telegram"]
        enqueued_count = 0

        subject = f"{sev.upper()}: {rule_name} on {dst_ip or 'Network'}"
        body = (
            f"Alert: {rule_name} (v{alert.get('rule_version', '?')})\n"
            f"Severity: {sev.upper()} | Confidence: {alert.get('confidence', 'heuristic')}\n"
            f"Endpoints: {alert.get('src_ip')}:{alert.get('src_port') or '—'} -> "
            f"{alert.get('dst_ip')}:{alert.get('dst_port') or '—'} ({alert.get('protocol')})\n"
            f"Detail: {alert.get('detail')}\n"
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.get('timestamp', now)))}\n"
        )

        with self._lock:
            cur = self._conn.cursor()
            for p_name in providers:
                p = self._providers.get(p_name.lower())
                if p is not None:
                    job_status = "pending" if p.is_configured else "unconfigured"
                    cur.execute(
                        """
                        INSERT INTO notification_outbox (
                            provider, recipient, subject, message_body, severity,
                            rule_name, alert_id, status, retry_count, max_retries, next_retry_at, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                        """,
                        (
                            p_name.lower(), getattr(p, "recipient", None), subject,
                            body, sev, rule_name, alert_id, job_status, self._max_retries, now, now
                        )
                    )
                    enqueued_count += 1
            self._conn.commit()
            cur.close()

        return enqueued_count

    def process_pending_outbox(self, max_items: int = 10) -> int:
        """
        Process pending outbox rows due for delivery with exponential backoff.
        Returns count of successfully delivered notifications.
        """
        if not self._conn:
            return 0

        now = time.time()
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT id, provider, recipient, subject, message_body, retry_count, max_retries
            FROM notification_outbox
            WHERE status = 'pending' AND next_retry_at <= ?
            ORDER BY next_retry_at ASC LIMIT ?
            """,
            (now, max_items)
        )
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()

        delivered = 0
        for r in rows:
            n_id = r["id"]
            p_name = r["provider"]
            p = self._providers.get(p_name)
            if not p:
                self._update_outbox_status(n_id, status="failed", error_message="Unknown provider")
                continue

            success, msg = p.send(r.get("recipient"), r["subject"], r["message_body"])
            if success:
                self._update_outbox_status(n_id, status="sent", sent_at=time.time())
                delivered += 1
            else:
                retry_count = r["retry_count"] + 1
                max_retries = r["max_retries"]
                if retry_count >= max_retries:
                    self._update_outbox_status(
                        n_id, status="dead", retry_count=retry_count, error_message=msg
                    )
                else:
                    backoff_delay = 2.0 ** retry_count
                    self._update_outbox_status(
                        n_id, status="pending", retry_count=retry_count,
                        next_retry_at=time.time() + backoff_delay, error_message=msg
                    )

        return delivered

    def _update_outbox_status(self, n_id: int, **kwargs):
        """Update notification record status."""
        if not self._conn:
            return
        set_parts = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [n_id]
        sql = f"UPDATE notification_outbox SET {', '.join(set_parts)} WHERE id = ?"
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, values)
            self._conn.commit()
            cur.close()

    def start_worker(self, interval_s: float = 2.0):
        """Start background daemon thread for outbox delivery."""
        if self._worker_thread and self._worker_thread.is_alive():
            return

        def _loop():
            while not self._stop_event.is_set():
                try:
                    self.process_pending_outbox()
                except Exception as exc:
                    logger.debug(f"Outbox worker iteration error: {exc}")
                self._stop_event.wait(interval_s)

        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=_loop, daemon=True)
        self._worker_thread.start()

    def stop_worker(self):
        """Stop background outbox thread."""
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=3)

    def send_test_notification(self, provider_name: str, recipient: str | None = None) -> dict[str, Any]:
        """Send a test diagnostic notification through the requested provider."""
        p = self._providers.get(provider_name.lower())
        if not p:
            return {"success": False, "provider": provider_name, "message": "Provider not supported"}
        if not p.is_configured:
            return {
                "success": False,
                "provider": provider_name,
                "message": f"Provider '{provider_name}' is not configured in environment / .env",
            }

        subj = "Diagnostic Test Alert"
        body = "This is a verified diagnostic test message from NetGuard IDS."
        ok, msg = p.send(recipient, subj, body)
        return {"success": ok, "provider": provider_name, "message": msg}
