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


def _is_postgres() -> bool:
    try:
        import config
        return getattr(config, "DB_BACKEND", "sqlite") == "postgres"
    except Exception:
        return False


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
        self._last_delivery: dict[str, float] = {}
        self._recent_errors: dict[str, list[str]] = {}
        self._lock = threading.Lock()

        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None

        if self._conn:
            self.reload_providers_from_db()

    def reload_providers_from_db(self):
        """Load configured notification provider credentials from persistent system settings."""
        if not self._conn:
            return
        from storage.forensics_db import get_system_setting
        for name in ("email", "telegram", "webhook", "sms"):
            try:
                cfg = get_system_setting(self._conn, f"notification_{name}")
                if cfg and isinstance(cfg, dict):
                    self.configure_provider(name, cfg, persist=False)
            except Exception as exc:
                logger.debug(f"Failed loading provider setting for {name}: {exc}")

    def configure_provider(self, name: str, cfg: dict, persist: bool = True) -> tuple[bool, str]:
        """Configure or update a notification provider with persistence."""
        name_lower = name.lower()
        if name_lower == "smtp":
            name_lower = "email"
        if name_lower not in self._providers:
            return False, f"Unknown provider '{name}'"

        current_p = self._providers[name_lower]

        if name_lower == "email":
            pwd = cfg.get("password")
            if (not pwd or pwd == "********") and hasattr(current_p, "password"):
                pwd = current_p.password
            self._providers["email"] = EmailProvider(
                host=cfg.get("host", ""),
                port=int(cfg.get("port") or 587),
                user=cfg.get("user", ""),
                password=pwd,
                from_addr=cfg.get("from_addr", ""),
                to_addr=cfg.get("to_addr", ""),
                use_tls=bool(cfg.get("use_tls", True)),
            )

        elif name_lower == "telegram":
            token = cfg.get("bot_token")
            if (not token or token == "********") and hasattr(current_p, "bot_token"):
                token = current_p.bot_token
            self._providers["telegram"] = TelegramProvider(
                bot_token=token,
                chat_id=cfg.get("chat_id", ""),
            )

        elif name_lower == "webhook":
            secret = cfg.get("secret")
            if (not secret or secret == "********") and hasattr(current_p, "secret"):
                secret = current_p.secret
            self._providers["webhook"] = WebhookProvider(
                url=cfg.get("url", ""),
                secret=secret,
            )

        elif name_lower == "sms":
            auth_token = cfg.get("auth_token")
            if (not auth_token or auth_token == "********") and hasattr(current_p, "auth_token"):
                auth_token = current_p.auth_token
            self._providers["sms"] = SmsProvider(
                account_sid=cfg.get("account_sid", ""),
                auth_token=auth_token,
                from_number=cfg.get("from_number", ""),
                to_number=cfg.get("to_number", ""),
            )

        if persist and self._conn:
            from storage.forensics_db import save_system_setting
            cfg_to_persist = dict(cfg)
            if name_lower == "email" and hasattr(current_p, "password") and current_p.password:
                if not cfg_to_persist.get("password") or cfg_to_persist.get("password") == "********":
                    cfg_to_persist["password"] = current_p.password
            elif name_lower == "telegram" and hasattr(current_p, "bot_token") and current_p.bot_token:
                if not cfg_to_persist.get("bot_token") or cfg_to_persist.get("bot_token") == "********":
                    cfg_to_persist["bot_token"] = current_p.bot_token
            elif name_lower == "webhook" and hasattr(current_p, "secret") and current_p.secret:
                if not cfg_to_persist.get("secret") or cfg_to_persist.get("secret") == "********":
                    cfg_to_persist["secret"] = current_p.secret
            elif name_lower == "sms" and hasattr(current_p, "auth_token") and current_p.auth_token:
                if not cfg_to_persist.get("auth_token") or cfg_to_persist.get("auth_token") == "********":
                    cfg_to_persist["auth_token"] = current_p.auth_token

            save_system_setting(self._conn, f"notification_{name_lower}", cfg_to_persist)

        return True, f"Configured {name_lower}"

    def get_provider_config(self, name: str) -> dict[str, Any]:
        """Return masked configuration for a provider."""
        name_lower = name.lower()
        if name_lower == "smtp":
            name_lower = "email"
        p = self._providers.get(name_lower)
        if not p:
            return {}
        if name_lower == "email":
            return {
                "host": getattr(p, "host", ""),
                "port": getattr(p, "port", 587),
                "user": getattr(p, "user", ""),
                "from_addr": getattr(p, "from_addr", ""),
                "to_addr": getattr(p, "to_addr", ""),
                "use_tls": getattr(p, "use_tls", True),
                "password_set": bool(getattr(p, "password", "")),
                "is_configured": p.is_configured,
                "has_recipient": p.has_recipient,
            }
        elif name.lower() == "telegram":
            return {
                "chat_id": getattr(p, "chat_id", ""),
                "bot_token_set": bool(getattr(p, "bot_token", "")),
                "is_configured": p.is_configured,
                "has_recipient": p.has_recipient,
            }
        elif name.lower() == "webhook":
            return {
                "url": getattr(p, "url", ""),
                "secret_set": bool(getattr(p, "secret", "")),
                "is_configured": p.is_configured,
                "has_recipient": p.has_recipient,
            }
        elif name.lower() == "sms":
            return {
                "account_sid": getattr(p, "account_sid", ""),
                "from_number": getattr(p, "from_number", ""),
                "to_number": getattr(p, "to_number", ""),
                "auth_token_set": bool(getattr(p, "auth_token", "")),
                "is_configured": p.is_configured,
                "has_recipient": p.has_recipient,
            }
        return {}

    def set_connection(self, conn):
        with self._lock:
            self._conn = conn

    def get_provider(self, name: str):
        return self._providers.get(name.lower())

    def get_providers_status(self) -> dict[str, dict[str, Any]]:
        """Return configuration and health status of all notification providers."""
        res = {}
        worker_running = self._worker_thread is not None and self._worker_thread.is_alive()
        for name, p in self._providers.items():
            res[name] = {
                "name": name,
                "configured": getattr(p, "is_configured", False),
                "recipient_configured": getattr(p, "has_recipient", False),
                "worker_running": worker_running,
                "last_delivery": self._last_delivery.get(name),
                "recent_errors": self._recent_errors.get(name, []),
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
            ph = "(%s, %s, %s, %s, %s, %s, %s, %s, 0, %s, %s, %s)" if _is_postgres() else "(?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)"
            insert_sql = f"""
                INSERT INTO notification_outbox (
                    provider, recipient, subject, message_body, severity,
                    rule_name, alert_id, status, retry_count, max_retries, next_retry_at, created_at
                )
                VALUES {ph}
            """
            for p_name in providers:
                p = self._providers.get(p_name.lower())
                if p is not None:
                    job_status = "pending" if p.is_configured else "unconfigured"
                    cur.execute(
                        insert_sql,
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
        ph = "%s" if _is_postgres() else "?"
        cur.execute(
            f"""
            SELECT id, provider, recipient, subject, message_body, retry_count, max_retries
            FROM notification_outbox
            WHERE status = 'pending' AND next_retry_at <= {ph}
            ORDER BY next_retry_at ASC LIMIT {ph}
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
                self._last_delivery[p_name] = time.time()
                delivered += 1
            else:
                retry_count = r["retry_count"] + 1
                max_retries = r["max_retries"]
                err_list = self._recent_errors.setdefault(p_name, [])
                err_list.append(str(msg))
                if len(err_list) > 10:
                    err_list.pop(0)

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
        ph = "%s" if _is_postgres() else "?"
        set_parts = [f"{k} = {ph}" for k in kwargs.keys()]
        values = list(kwargs.values()) + [n_id]
        sql = f"UPDATE notification_outbox SET {', '.join(set_parts)} WHERE id = {ph}"
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
            self._worker_thread = None

    def send_test_notification(self, provider_name: str, recipient: str | None = None, custom_cfg: dict | None = None) -> dict[str, Any]:
        """Send a test diagnostic notification through the requested provider."""
        name_lower = provider_name.lower()
        if name_lower == "smtp":
            name_lower = "email"
        p = self._providers.get(name_lower)
        if not p:
            return {"success": False, "provider": provider_name, "message": "Provider not supported"}

        # If custom configuration is provided for testing, use a temporary provider instance
        if custom_cfg and isinstance(custom_cfg, dict):
            if name_lower == "email":
                p = EmailProvider(
                    host=custom_cfg.get("host", getattr(p, "host", "")),
                    port=int(custom_cfg.get("port") or getattr(p, "port", 587)),
                    user=custom_cfg.get("user", getattr(p, "user", "")),
                    password=custom_cfg.get("password") or getattr(p, "password", ""),
                    from_addr=custom_cfg.get("from_addr", getattr(p, "from_addr", "")),
                    to_addr=custom_cfg.get("to_addr", getattr(p, "to_addr", "")),
                    use_tls=bool(custom_cfg.get("use_tls", getattr(p, "use_tls", True))),
                )
            elif name_lower == "telegram":
                p = TelegramProvider(
                    bot_token=custom_cfg.get("bot_token") or getattr(p, "bot_token", ""),
                    chat_id=custom_cfg.get("chat_id", getattr(p, "chat_id", "")),
                )
            elif name_lower == "webhook":
                p = WebhookProvider(
                    url=custom_cfg.get("url", getattr(p, "url", "")),
                    secret=custom_cfg.get("secret") or getattr(p, "secret", ""),
                )
            elif name_lower == "sms":
                p = SmsProvider(
                    account_sid=custom_cfg.get("account_sid", getattr(p, "account_sid", "")),
                    auth_token=custom_cfg.get("auth_token") or getattr(p, "auth_token", ""),
                    from_number=custom_cfg.get("from_number", getattr(p, "from_number", "")),
                    to_number=custom_cfg.get("to_number", getattr(p, "to_number", "")),
                )

        if not p.is_configured:
            return {
                "success": False,
                "provider": provider_name,
                "message": f"Provider '{provider_name}' is not configured (missing host, from-address, token, or URL)",
            }

        subj = "Diagnostic Test Alert"
        body = "This is a verified diagnostic test message from NetGuard IDS."
        ok, msg = p.send(recipient, subj, body)
        return {"success": ok, "provider": provider_name, "message": msg}


_global_outbox_manager: NotificationOutboxManager | None = None


def get_outbox_manager(conn=None) -> NotificationOutboxManager:
    global _global_outbox_manager
    if _global_outbox_manager is None:
        _global_outbox_manager = NotificationOutboxManager(conn=conn)
    elif conn is not None and _global_outbox_manager._conn is None:
        _global_outbox_manager.set_connection(conn)
    return _global_outbox_manager


def on_alert_persisted(conn, alert: dict, alert_id: int | None = None):
    """Hook invoked by storage.db.write_alert to enqueue notifications for qualifying alerts."""
    if alert.get("_is_offline_replay") or getattr(conn, "_is_offline_replay", False):
        return
    mgr = get_outbox_manager(conn=conn)
    if mgr:
        try:
            mgr.enqueue_alert(alert, alert_id=alert_id)
        except Exception as exc:
            logger.debug(f"Failed to enqueue alert notification: {exc}")
