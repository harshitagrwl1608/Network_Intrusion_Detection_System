"""
notifications/outbox.py
-----------------------
Asynchronous notification outbox with rate-limiting, deduplication,
exponential backoff retries, provider routing, crash recovery and
permanent/transient failure classification.
"""

import os
import time
import json
import logging
import threading
from typing import Any

from notifications.providers import (
    EmailProvider, TelegramProvider, WebhookProvider, SmsProvider
)
from notifications.email_render import (
    render_alert_email,
    render_report_email,
)

logger = logging.getLogger(__name__)

# A row claimed by a worker transitions to 'sending'. If the process dies mid
# delivery, the claim is reclaimed after this grace period.
STALE_CLAIM_SECONDS = 300.0

# Bounded snapshot of an alert kept on the outbox row so a rich HTML body can be
# rendered at delivery time without storing rendered markup.
ALERT_PAYLOAD_MAX_DETAIL = 4000
MAX_BACKOFF_SECONDS = 3600.0

_ALERT_PAYLOAD_FIELDS = (
    "rule_name", "rule_version", "severity", "confidence",
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "detail", "timestamp", "flow_id", "evidence_json", "country",
    "assigned_case_id", "case_id",
)


def _is_postgres() -> bool:
    try:
        import config
        return getattr(config, "DB_BACKEND", "sqlite") == "postgres"
    except Exception:
        return False


def _dashboard_base_url() -> str | None:
    """Return the configured dashboard base URL, if any.

    Only an explicit configuration produces a link in outgoing email; a
    localhost default would generate links that are useless to recipients.
    """
    candidate = os.getenv("NETGUARD_DASHBOARD_URL", "").strip()
    if candidate:
        return candidate
    try:
        import config

        if getattr(config, "DASHBOARD_PUBLIC_URL", ""):
            return str(config.DASHBOARD_PUBLIC_URL)
    except Exception:
        pass
    return None



class NotificationOutboxManager:
    """
    Manages non-blocking outbox enqueueing and asynchronous background delivery.
    """

    def __init__(self, conn=None, min_severity: str = "high",
                 cooldown_s: float = 300.0, max_retries: int = 3,
                 main_conn=None, cooldown_seconds=None):
        self._conn = conn if conn is not None else main_conn
        # Operators can raise or lower the notification floor without a code
        # change; the default preserves historical behaviour (high and above).
        configured_severity = os.getenv("NOTIFICATION_MIN_SEVERITY", "").strip().lower()
        self._min_severity = (configured_severity or min_severity).lower()
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
        self._dashboard_url = _dashboard_base_url()

        if self._conn:
            self.reload_providers_from_db()

    def reload_providers_from_db(self):
        """Load configured notification provider credentials from persistent system settings. Fails closed."""
        if not self._conn:
            return
        from storage.forensics_db import get_system_setting
        for name in ("email", "telegram", "webhook", "sms"):
            try:
                cfg = get_system_setting(self._conn, f"notification_{name}", raise_on_error=True)
                if cfg and isinstance(cfg, dict):
                    self.configure_provider(name, cfg, persist=False)
            except Exception as exc:
                logger.warning(f"Failed loading/decrypting provider setting for {name} ({exc}). Provider remains unconfigured.")

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
                from_name=cfg.get("from_name", "NetGuard IDS"),
                to_addr=cfg.get("to_addr", ""),
                cc_addr=cfg.get("cc_addr", ""),
                bcc_addr=cfg.get("bcc_addr", ""),
                use_tls=bool(cfg.get("use_tls", True)),
                tls_mode=cfg.get("tls_mode") or None,
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
            from storage.crypto import CryptoError
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

            try:
                save_system_setting(self._conn, f"notification_{name_lower}", cfg_to_persist)
            except CryptoError as exc:
                logger.error(f"Failed to persist {name_lower} configuration due to encryption error: {exc}")
                return False, f"Encryption configuration error: {exc}"
            except Exception as exc:
                logger.error(f"Failed to persist {name_lower} configuration: {exc}")
                return False, f"Failed to persist configuration: {exc}"

        # Re-queue jobs that were parked because the provider had no credentials
        # at enqueue time. Without this, alerts raised before configuration are
        # silently stranded forever.
        requeued = 0
        try:
            new_provider = self._providers.get(name_lower)
            if self._conn and new_provider is not None and new_provider.is_configured:
                requeued = self.requeue_unconfigured(name_lower)
        except Exception as exc:
            logger.debug(f"Failed to re-queue unconfigured jobs for {name_lower}: {exc}")

        if requeued:
            return True, f"Configured {name_lower} and re-queued {requeued} pending notification(s)"
        return True, f"Configured {name_lower}"

    def requeue_unconfigured(self, provider_name: str | None = None) -> int:
        """Move 'unconfigured' outbox rows back to pending. Returns the count."""
        if not self._conn:
            return 0
        ph = "%s" if _is_postgres() else "?"
        sql = (
            "UPDATE notification_outbox SET status = 'pending', next_retry_at = "
            f"{ph}, error_message = NULL WHERE status = 'unconfigured'"
        )
        params: list[Any] = [time.time()]
        if provider_name:
            sql += f" AND provider = {ph}"
            params.append(provider_name.lower())

        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, params)
            count = cur.rowcount or 0
            self._conn.commit()
            cur.close()
        if count:
            logger.info(
                f"Re-queued {count} previously unconfigured "
                f"{provider_name or 'provider'} notification(s)"
            )
        return count

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
                "from_name": getattr(p, "from_name", "NetGuard IDS"),
                "to_addr": getattr(p, "to_addr", ""),
                "cc_addr": getattr(p, "cc_addr", ""),
                "bcc_addr": getattr(p, "bcc_addr", ""),
                "use_tls": getattr(p, "use_tls", True),
                "tls_mode": getattr(p, "tls_mode", "starttls"),
                "password_set": bool(getattr(p, "password", "")),
                "auth_required_but_missing": bool(getattr(p, "auth_required_but_missing", False)),
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

    def _build_alert_payload(self, alert: dict) -> dict:
        """Snapshot the alert fields needed to render a professional email.

        The snapshot is deliberately bounded: ``detail`` is truncated and no
        payload bytes are ever copied.
        """
        snapshot: dict[str, Any] = {}
        for key in _ALERT_PAYLOAD_FIELDS:
            if key not in alert:
                continue
            value = alert.get(key)
            if value is None:
                continue
            if key == "detail":
                value = str(value)[:ALERT_PAYLOAD_MAX_DETAIL]
            elif key == "evidence_json":
                raw = value if isinstance(value, (str, bytes)) else json.dumps(value, default=str)
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", "replace")
                value = str(raw)[:ALERT_PAYLOAD_MAX_DETAIL * 2]
            snapshot[key] = value
        return snapshot

    def _recipients_for(self, provider_name: str, provider) -> tuple[str, list, list]:
        """Resolve the To/Cc/Bcc triple for a provider.

        Values are coerced to strings so a partially configured (or mocked)
        provider can never inject a non-string object into the outbox row.
        """
        if provider_name == "email":
            to = getattr(provider, "to_addr", "")
            if not isinstance(to, str) or not to.strip():
                to = getattr(provider, "recipient", "")
            if not isinstance(to, str):
                to = ""
            return to, [], []

        rec = getattr(provider, "recipient", None)
        return (rec if isinstance(rec, str) else None), [], []

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

        # Render once so every provider sees identical content.
        rendered = render_alert_email(
            alert,
            alert_id=alert_id,
            dashboard_base_url=self._dashboard_url,
        )
        payload = json.dumps(
            {"kind": "alert", "alert": self._build_alert_payload(alert)},
            default=str,
        )[:65536]

        with self._lock:
            cur = self._conn.cursor()
            ph = "(%s, %s, %s, %s, %s, %s, %s, %s, 0, %s, %s, %s, %s)" if _is_postgres() else "(?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)"
            insert_sql = f"""
                INSERT INTO notification_outbox (
                    provider, recipient, subject, message_body, severity,
                    rule_name, alert_id, status, retry_count, max_retries,
                    next_retry_at, created_at, payload_json
                )
                VALUES {ph}
            """
            for p_name in providers:
                p = self._providers.get(p_name.lower())
                if p is not None:
                    job_status = "pending" if p.is_configured else "unconfigured"
                    target, _, _ = self._recipients_for(p_name.lower(), p)
                    cur.execute(
                        insert_sql,
                        (
                            p_name.lower(), target, rendered.subject,
                            rendered.text, sev, rule_name, alert_id, job_status,
                            self._max_retries, now, now, payload,
                        )
                    )
                    enqueued_count += 1
            self._conn.commit()
            cur.close()

        return enqueued_count

    def enqueue_report_email(self, artifact, *, report_payload: dict,
                             subject: str, text_body: str, html_body: str,
                             to: str, cc: str = "", bcc: str = "",
                             severity: str = "medium") -> int:
        """Queue one report delivery job. Returns the number of jobs created."""
        if not self._conn:
            raise RuntimeError("Outbox is not connected to a database")

        provider = self._providers.get("email")
        if provider is None:
            raise RuntimeError("Email provider is not available")

        payload = dict(report_payload or {})
        payload["cc"] = cc or ""
        payload["bcc"] = bcc or ""

        now = time.time()
        ph = "(%s, %s, %s, %s, %s, %s, %s, %s, 0, %s, %s, %s, %s)" if _is_postgres() else "(?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)"
        sql = f"""
            INSERT INTO notification_outbox (
                provider, recipient, subject, message_body, severity,
                rule_name, alert_id, status, retry_count, max_retries,
                next_retry_at, created_at, payload_json
            )
            VALUES {ph}
        """
        job_status = "pending" if (provider.is_configured and to) else "unconfigured"
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                sql,
                (
                    "email", to, subject, text_body, (severity or "medium").lower(),
                    "REPORT", None, job_status, self._max_retries, now, now,
                    json.dumps(payload, default=str)[:65536],
                )
            )
            self._conn.commit()
            cur.close()
        return 1

    def process_pending_outbox(self, max_items: int = 10) -> int:
        """
        Process pending outbox rows due for delivery with exponential backoff.

        Each row is claimed atomically (``pending`` -> ``sending``) so two
        workers cannot deliver the same job, and a crashed worker's claim is
        reclaimed by :meth:`recover_stale_claims`.

        Returns count of successfully delivered notifications.
        """
        if not self._conn:
            return 0

        now = time.time()
        ph = "%s" if _is_postgres() else "?"
        cur = self._conn.cursor()
        cur.execute(
            f"""
            SELECT id, provider, recipient, subject, message_body, retry_count,
                   max_retries, payload_json
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

            if not self._claim_job(n_id):
                # Another worker took it; skip without touching state.
                continue

            payload = self._decode_payload(r.get("payload_json"))
            ok, msg, extra = self._deliver_one(p, p_name, r, payload)

            if ok:
                self._update_outbox_status(
                    n_id, status="sent", sent_at=time.time(),
                    error_message=(msg if extra.get("partial") else None),
                )
                self._last_delivery[p_name] = time.time()
                delivered += 1
            else:
                self._handle_failure(n_id, p_name, r, payload, msg, extra)

        return delivered

    # -- delivery helpers -------------------------------------------------

    def _decode_payload(self, raw) -> dict | None:
        if not raw:
            return None
        if isinstance(raw, dict):
            return raw
        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except (ValueError, TypeError):
            return None

    def _claim_job(self, job_id: int) -> bool:
        """Atomically transition one row from pending to sending."""
        ph = "%s" if _is_postgres() else "?"
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                f"UPDATE notification_outbox SET status = 'sending', next_retry_at = {ph} "
                f"WHERE id = {ph} AND status = 'pending'",
                (time.time(), job_id),
            )
            claimed = cur.rowcount == 1
            self._conn.commit()
            cur.close()
        return claimed

    def recover_stale_claims(self, stale_after_s: float = STALE_CLAIM_SECONDS) -> int:
        """Return orphaned 'sending' rows to pending after a crash."""
        if not self._conn:
            return 0
        ph = "%s" if _is_postgres() else "?"
        cutoff = time.time() - stale_after_s
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                f"UPDATE notification_outbox SET status = 'pending', "
                f"next_retry_at = {ph} "
                f"WHERE status = 'sending' AND next_retry_at <= {ph}",
                (time.time(), cutoff),
            )
            count = cur.rowcount or 0
            self._conn.commit()
            cur.close()
        if count:
            logger.warning(f"Recovered {count} stale in-flight notification(s) after restart")
        return count

    def _deliver_one(self, provider, provider_name: str, row: dict,
                     payload: dict | None) -> tuple[bool, str, dict]:
        """Deliver a single outbox row, rendering rich HTML when payload exists."""
        extra: dict[str, Any] = {}

        if provider_name != "email" or not payload:
            ok, msg = provider.send(row.get("recipient"), row["subject"], row["message_body"])
            if isinstance(getattr(provider, "last_detail", None), dict):
                extra.update(provider.last_detail)
            return ok, msg, extra

        kind = str(payload.get("kind") or "")
        cc_raw = payload.get("cc") or ""
        bcc_raw = payload.get("bcc") or ""

        try:
            if kind == "alert":
                rendered = render_alert_email(
                    payload.get("alert") or {},
                    alert_id=row.get("alert_id"),
                    dashboard_base_url=self._dashboard_url,
                )
            elif kind == "report":
                report = payload.get("report") or {}
                rendered = render_report_email(
                    report_title=report.get("title") or row["subject"],
                    report_type=report.get("type") or "daily",
                    fmt=report.get("format") or "html",
                    filename=(payload.get("attachment") or {}).get("filename")
                             or "netguard_report",
                    hours=int(report.get("hours") or 24),
                    recipient_count=1,
                    dashboard_base_url=self._dashboard_url,
                    generated_at=report.get("generated_at"),
                    summary_rows=[tuple(x) for x in (report.get("summary_rows") or [])],
                )
            else:
                ok, msg = provider.send(row.get("recipient"), row["subject"], row["message_body"])
                return ok, msg, extra
        except Exception as exc:
            logger.error(f"Email rendering failed for outbox row {row.get('id')}: {exc}")
            return False, f"Email rendering failed: {exc}", {"transient": False}

        attachments = []
        if kind == "report":
            att = payload.get("attachment") or {}
            try:
                from notifications.report_delivery import resolve_artifact_path

                resolved = resolve_artifact_path(att.get("path"))
                attachments.append({
                    "path": resolved,
                    "filename": att.get("filename") or "netguard_report",
                    "mime": att.get("mime") or "application/octet-stream",
                })
            except Exception as exc:
                # The attachment is gone (pruned) or invalid. Send the covering
                # email without it rather than failing silently, and say so.
                logger.warning(f"Report attachment unavailable for row {row.get('id')}: {exc}")
                extra["attachment_missing"] = True

        ok, msg = provider.send(
            row.get("recipient"),
            rendered.subject,
            rendered.text,
            html_body=rendered.html,
            cc=cc_raw,
            bcc=bcc_raw,
            attachments=attachments,
        )
        detail = getattr(provider, "last_detail", None)
        if isinstance(detail, dict):
            extra.update(detail)
        return ok, msg, extra

    def _handle_failure(self, n_id: int, provider_name: str, row: dict,
                        payload: dict | None, msg: str, extra: dict) -> None:
        """Classify a failure and either schedule a retry or mark it dead."""
        retry_count = int(row["retry_count"] or 0) + 1
        max_retries = int(row["max_retries"] or self._max_retries)

        err_list = self._recent_errors.setdefault(provider_name, [])
        err_list.append(str(msg))
        if len(err_list) > 10:
            err_list.pop(0)

        transient = extra.get("transient", True)
        error_class = extra.get("error_class")

        # Permanent failures (bad credentials, rejected recipients, malformed
        # address) will not succeed on retry: stop immediately and surface the
        # reason instead of burning the retry budget.
        if error_class in ("auth", "permanent") or transient is False:
            self._update_outbox_status(
                n_id, status="failed", retry_count=retry_count,
                error_message=f"{error_class or 'permanent'}: {msg}"[:1000],
            )
            logger.warning(
                f"Notification {n_id} failed permanently via {provider_name}: {msg}"
            )
            return

        if retry_count >= max_retries:
            self._update_outbox_status(
                n_id, status="dead", retry_count=retry_count,
                error_message=str(msg)[:1000],
            )
            logger.warning(f"Notification {n_id} exhausted {max_retries} retries via {provider_name}")
            return

        # Exponential backoff with a bounded ceiling and per-row jitter so a
        # batch of failures does not retry in lockstep.
        delay = min(2.0 ** retry_count, MAX_BACKOFF_SECONDS)
        jitter = (hash(n_id) % 1000) / 1000.0
        self._update_outbox_status(
            n_id, status="pending", retry_count=retry_count,
            next_retry_at=time.time() + delay + jitter,
            error_message=str(msg)[:1000],
        )

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

        # Recover claims orphaned by a crash before this process started.
        try:
            self.recover_stale_claims()
        except Exception as exc:
            logger.debug(f"Stale claim recovery skipped: {exc}")

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

    def get_outbox_stats(self) -> dict[str, Any]:
        """Return delivery-state counters for operational visibility."""
        if not self._conn:
            return {}
        try:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT status, COUNT(*) FROM notification_outbox GROUP BY status"
            )
            counts = {str(row[0]): int(row[1]) for row in cur.fetchall()}
            cur.close()
        except Exception as exc:
            logger.debug(f"Outbox stats unavailable: {exc}")
            return {}
        pending = counts.get("pending", 0) + counts.get("sending", 0)
        return {
            "counts": counts,
            "pending": pending,
            "sent": counts.get("sent", 0),
            "failed": counts.get("failed", 0),
            "dead": counts.get("dead", 0),
            "unconfigured": counts.get("unconfigured", 0),
        }

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
                    from_name=custom_cfg.get("from_name", getattr(p, "from_name", "NetGuard IDS")),
                    to_addr=custom_cfg.get("to_addr", getattr(p, "to_addr", "")),
                    cc_addr=custom_cfg.get("cc_addr", getattr(p, "cc_addr", "")),
                    bcc_addr=custom_cfg.get("bcc_addr", getattr(p, "bcc_addr", "")),
                    use_tls=bool(custom_cfg.get("use_tls", getattr(p, "use_tls", True))),
                    tls_mode=custom_cfg.get("tls_mode") or getattr(p, "tls_mode", None),
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
                "diagnostics": p.describe() if hasattr(p, "describe") else {},
            }

        subj = "Diagnostic Test Alert"
        body = "This is a verified diagnostic test message from NetGuard IDS."
        kwargs: dict[str, Any] = {}
        if name_lower == "email":
            rendered = render_alert_email(
                {
                    "rule_name": "DIAGNOSTIC_TEST",
                    "severity": "info",
                    "confidence": "test",
                    "detail": (
                        "This is a diagnostic message generated from the NetGuard IDS "
                        "notification settings screen. No detection rule fired."
                    ),
                    "timestamp": time.time(),
                },
                dashboard_base_url=self._dashboard_url,
            )
            subj = rendered.subject
            body = rendered.text
            kwargs["html_body"] = rendered.html

        ok, msg = p.send(recipient, subj, body, **kwargs)
        result = {
            "success": ok,
            "provider": provider_name,
            "message": msg,
        }
        if name_lower == "email":
            result["diagnostics"] = p.describe()
            detail = getattr(p, "last_detail", None)
            if isinstance(detail, dict) and detail:
                result["delivery"] = {
                    "error_class": detail.get("error_class"),
                    "transient": detail.get("transient"),
                    "partial": detail.get("partial", False),
                }
        return result


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
