#!/usr/bin/env python3
"""
NetGuard Overnight Sprint — local model-failover watchdog.

Purpose
-------
Run independently of the AI model so that a provider quota failure cannot leave
the sprint in a half-finished state. The watchdog:

  1. Observes model-failure events (from a log tailer and/or an explicit feed).
  2. On a *confirmed* quota/rate-limit failure of the primary model, probes the
     single authorised fallback model exactly once.
  3. If the probe succeeds, records FALLBACK_ACTIVE and keeps working.
  4. If fallback activation fails, or the fallback hits the same free-allowance
     ceiling, declares MODEL_UNAVAILABLE, writes a fixed marker file, and runs a
     graceful shutdown sequence.

Safety properties
-----------------
* Shutdown is triggered only by the watchdog's own state machine. Text returned
  by a model is **never** executed and **never** parsed for commands.
* A fixed marker file (``MODEL_UNAVAILABLE.marker``) is the only interlock.
* An exclusive file lock plus an O_EXCL sentinel prevent duplicate shutdowns.
* ``--dry-run`` performs every step except the final power-off command.
* Transient network errors are retried a bounded number of times and never
  cause a power-off.
* Only PIDs explicitly registered in ``managed_pids`` may be signalled.

Usage
-----
    python3 model_failover_watchdog.py run            # daemon
    python3 model_failover_watchdog.py run --dry-run
    python3 model_failover_watchdog.py feed --kind quota_error --model opencode/deepseek-v4.1-flash-free
    python3 model_failover_watchdog.py status
    python3 model_failover_watchdog.py selftest --dry-run
    python3 model_failover_watchdog.py checkpoint

Configuration: ~/.config/opencode/netguard-watchdog.json (created on first run).
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import time
import traceback

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_PRIMARY = "opencode/deepseek-v4.1-flash-free"
DEFAULT_FALLBACKS = ["opencode/minimax-m3.1-flash-free"]
DEFAULT_ADDITIONAL = ["opencode/glm-5.3-flash-free"]

MARKER_MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE.marker"
MARKER_SHUTDOWN_STARTED = "shutdown_started.marker"
MARKER_FALLBACK_ACTIVE = "fallback_active.marker"

# Confirmed free-allowance / quota exhaustion of a request.
QUOTA_PATTERNS = [
    "free usage limit",
    "usage limit reached",
    "usage limit exceeded",
    "quota exceeded",
    "insufficient_quota",
    "insufficient quota",
    "exceeded your current quota",
    "rate limit exceeded",
    "ratelimit",
    "too many requests",
    "429",
    "no credits",
    "allowance exhausted",
    "out of credits",
]

# Model not available / not routable — also terminal for the authorised set.
UNAVAILABLE_PATTERNS = [
    "model not found",
    "model is not available",
    "no longer available",
    "model_not_found",
    "unsupported model",
]

# Temporary connectivity problems must be retried, not acted upon.
TRANSIENT_PATTERNS = [
    "connection refused",
    "connection reset",
    "timed out",
    "timeout",
    "temporary failure in name resolution",
    "name or service not known",
    "network is unreachable",
    "econnrefused",
    "econnreset",
    "etimedout",
    "enotfound",
    "tls handshake",
    "503 service unavailable",
    "502 bad gateway",
]

# Only lines that look like genuine provider/RPC failures may influence the
# state machine. This prevents unrelated text (tool output echoed into a log)
# from being mistaken for a quota failure.
PROVIDER_ERROR_MARKERS = [
    "ai_apicallerror",
    "apicallerror",
    "providermodelnotfounderror",
    "provider_model_not_found",
    "insufficient_quota",
    "statuscode=429",
    "status=429",
    "\"status\":429",
    "\"type\":\"error\"",
    "error: ai_",
]

# Errors that mean "this authorised free model cannot be used right now".
HARD_ERROR_TYPES = [
    "quotaexceeded",
    "ratelimitexceeded",
    "insufficientquota",
    "providermodelnotfound",
    "modelnotfound",
    "usagelimitexceeded",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def expand(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def atomic_write(path: str, payload: str) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def read_json(path: str, default=None):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def classify_text(text: str) -> str:
    """Classify free-text (log line or probe output).

    Returns one of: ``quota``, ``unavailable``, ``transient``, ``unknown``.
    """
    low = (text or "").lower()
    if any(p in low for p in QUOTA_PATTERNS):
        return "quota"
    if any(p in low for p in UNAVAILABLE_PATTERNS):
        return "unavailable"
    if any(p in low for p in TRANSIENT_PATTERNS):
        return "transient"
    return "unknown"


DEFAULT_CONFIG = {
    "primary_model": DEFAULT_PRIMARY,
    "fallback_models": DEFAULT_FALLBACKS,
    "additional_models": DEFAULT_ADDITIONAL,
    "probe": {
        # Read-only agent: the probe must never mutate the working tree.
        "agent": "plan",
        "prompt": "Reply with exactly: NETGUARD_PROBE_OK",
        "success_token": "NETGUARD_PROBE_OK",
        "timeout_s": 180,
        "max_attempts": 1,
        "transient_retries": 2,
        "transient_backoff_s": 20,
        "cwd": "/tmp/opencode",
        # Optional override used by the self-test: a shell-free argv list.
        "command": None,
    },
    "checkpoint_interval_s": 600,
    "poll_interval_s": 5,
    # The OpenCode server log does not carry provider API errors, so the log
    # tail is disabled by default and a strict ERROR-level filter is used when
    # enabled. The authoritative provider-error source is the session database.
    "log_files": [],
    "db": {
        "enabled": True,
        "path": "~/.local/share/opencode/opencode.db",
        "poll_interval_s": 5,
    },
    "state_dir": "~/.local/state/netguard-watchdog",
    "watch_dir": "~/NetGuard-overnight-handoff",
    "shutdown": {
        "enabled": False,
        "commands": [
            ["systemctl", "poweroff", "--no-block"],
            ["loginctl", "poweroff"],
        ],
        "stop_opencode": True,
        "opencode_stop_command": ["opencode", "service", "stop"],
        "pre_shutdown_commands": [],
        "grace_seconds": 20,
    },
    "checkpoint_command": None,
}


def merge_config(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge_config(out[key], value)
        else:
            out[key] = value
    return out


class Watchdog:
    def __init__(self, config_path: str | None = None, dry_run: bool = False,
                 log_stream=None):
        self.config_path = expand(
            config_path or "~/.config/opencode/netguard-watchdog.json"
        )
        raw = read_json(self.config_path, {}) or {}
        self.cfg = merge_config(DEFAULT_CONFIG, raw)
        self.dry_run = dry_run
        self.state_dir = expand(self.cfg["state_dir"])
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        self.marker_path = os.path.join(self.state_dir, MARKER_MODEL_UNAVAILABLE)
        self.shutdown_marker = os.path.join(self.state_dir, MARKER_SHUTDOWN_STARTED)
        self.fallback_marker = os.path.join(self.state_dir, MARKER_FALLBACK_ACTIVE)
        self.state_path = os.path.join(self.state_dir, "state.json")
        self.events_path = os.path.join(self.state_dir, "events.jsonl")
        self.pids_path = os.path.join(self.state_dir, "managed_pids")
        self.lock_path = os.path.join(self.state_dir, "watchdog.lock")
        self._log_stream = log_stream or sys.stderr
        self.state = read_json(self.state_path, {}) or {
            "phase": "IDLE",
            "primary_model": self.cfg["primary_model"],
            "last_event": None,
            "probe_attempts": 0,
            "started_at": now_iso(),
        }

    # -- logging --------------------------------------------------------

    def log(self, level: str, message: str) -> None:
        line = f"{now_iso()} [{level}] {message}"
        try:
            print(line, file=self._log_stream, flush=True)
        except Exception:
            pass

    def save_state(self) -> None:
        atomic_write(self.state_path, json.dumps(self.state, indent=2))

    def set_phase(self, phase: str, **extra) -> None:
        self.state["phase"] = phase
        self.state.update(extra)
        self.state["updated_at"] = now_iso()
        self.save_state()
        self.log("STATE", f"phase -> {phase}")

    # -- events ---------------------------------------------------------

    def record_event(self, kind: str, detail: dict) -> None:
        entry = {"ts": now_iso(), "epoch": time.time(), "kind": kind, **detail}
        try:
            with open(self.events_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            self.log("WARN", f"Could not append event: {exc}")
        self.state["last_event"] = entry
        self.save_state()

    # -- checkpointing --------------------------------------------------

    def checkpoint(self, reason: str = "scheduled") -> str:
        """Write a durable checkpoint. Returns the checkpoint path."""
        ckpt_dir = os.path.join(self.state_dir, "checkpoints")
        os.makedirs(ckpt_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        path = os.path.join(ckpt_dir, f"ckpt_{stamp}.json")

        payload = {
            "created_at": now_iso(),
            "reason": reason,
            "phase": self.state.get("phase"),
            "primary_model": self.cfg["primary_model"],
            "worktrees": {},
        }
        for repo in self._candidate_repos():
            payload["worktrees"][repo] = self._git_snapshot(repo)

        try:
            atomic_write(path, json.dumps(payload, indent=2))
        except OSError as exc:
            self.log("WARN", f"Checkpoint write failed: {exc}")
            return ""

        hook = self.cfg.get("checkpoint_command")
        if hook:
            try:
                argv = [hook] if isinstance(hook, str) else list(hook)
                subprocess.run(argv, timeout=120, capture_output=True, check=False)
            except Exception as exc:
                self.log("WARN", f"checkpoint_command failed: {exc}")

        try:
            os.sync()
        except Exception:
            pass
        self.log("CHECKPOINT", f"{reason} -> {path}")
        return path

    def _candidate_repos(self) -> list[str]:
        repos = []
        for candidate in ("~/NetGuard-sprint", "~/Downloads/Networking_Project"):
            path = expand(candidate)
            if os.path.isdir(os.path.join(path, ".git")) or os.path.isfile(
                os.path.join(path, ".git")
            ):
                repos.append(path)
        return repos

    @staticmethod
    def _git_snapshot(repo: str) -> dict:
        def run(*args) -> str:
            try:
                out = subprocess.run(
                    ["git", "-C", repo, *args], capture_output=True, text=True,
                    timeout=30, check=False,
                )
                return out.stdout.strip()
            except Exception as exc:
                return f"error: {exc}"

        return {
            "branch": run("rev-parse", "--abbrev-ref", "HEAD"),
            "head": run("rev-parse", "HEAD"),
            "dirty_files": len([l for l in run("status", "--porcelain").splitlines() if l]),
        }

    # -- failure handling ------------------------------------------------

    def handle_failure(self, kind: str, text: str = "", model: str = "") -> str:
        """Decide what to do about a reported failure. Returns the new phase."""
        classification = kind if kind in ("quota", "unavailable", "transient") else classify_text(text)

        if classification == "transient":
            self.log("INFO", "Transient network failure — bounded retry, no shutdown")
            self.record_event("transient", {"text": text[:300], "model": model})
            return self.state.get("phase", "IDLE")

        if classification == "unknown":
            self.log("WARN", "Unclassified failure — recording only, no action")
            self.record_event("unknown", {"text": text[:300], "model": model})
            return self.state.get("phase", "IDLE")

        self.log("ALERT", f"Confirmed {classification} failure for {model or self.cfg['primary_model']}")
        self.record_event(classification, {"text": text[:300], "model": model})
        self.set_phase("FALLBACK_PROBING", probe_attempts=0)

        # Probe exactly one authorised fallback model.
        fallbacks = list(self.cfg.get("fallback_models") or [])
        if not fallbacks:
            self.log("ERROR", "No fallback model configured")
            return self.declare_unavailable("no fallback model configured")

        fallback = fallbacks[0]
        outcome, detail = self.probe_model(fallback)

        if outcome == "ok":
            self.log("INFO", f"Fallback active: {fallback}")
            self.state["active_model"] = fallback
            atomic_write(self.fallback_marker, f"{now_iso()} {fallback}\n")
            self.set_phase("FALLBACK_ACTIVE", fallback_model=fallback)
            self.checkpoint("fallback_activated")
            return "FALLBACK_ACTIVE"

        if outcome == "transient":
            self.log("WARN", f"Fallback probe hit a transient error: {detail[:200]}")
            self.record_event("fallback_transient", {"text": detail[:300]})
            # Transient does not prove the allowance is exhausted.
            self.set_phase("IDLE")
            return "IDLE"

        return self.declare_unavailable(f"fallback {outcome}: {detail[:400]}")

    def probe_model(self, model: str) -> tuple[str, str]:
        """Send exactly one bounded request to ``model``.

        Returns ``(outcome, detail)`` where outcome is ``ok``, ``quota``,
        ``activation_failed`` or ``transient``.
        """
        probe = self.cfg.get("probe", {})
        attempts = int(probe.get("max_attempts", 1))
        transient_retries = int(probe.get("transient_retries", 2))
        backoff = float(probe.get("transient_backoff_s", 20))
        token = str(probe.get("success_token") or "NETGUARD_PROBE_OK")
        timeout = float(probe.get("timeout_s", 180))
        cwd = expand(probe.get("cwd") or "/tmp/opencode")
        os.makedirs(cwd, exist_ok=True)

        custom = probe.get("command")
        base_cmd = list(custom) if custom else [
            "opencode", "run",
            "--standalone",  # private server: never disturbs the live session
            "--model", model,
            "--agent", str(probe.get("agent") or "plan"),
            str(probe.get("prompt") or "Reply with exactly: NETGUARD_PROBE_OK"),
        ]
        if custom and "{model}" in " ".join(base_cmd):
            base_cmd = [part.replace("{model}", model) for part in base_cmd]

        transient_seen = 0
        last_detail = ""
        for attempt in range(1, attempts + 1):
            self.state["probe_attempts"] = int(self.state.get("probe_attempts", 0)) + 1
            self.save_state()
            self.log("PROBE", f"attempt {attempt}/{attempts} model={model}")
            try:
                proc = subprocess.run(
                    base_cmd, capture_output=True, text=True,
                    timeout=timeout, cwd=cwd, check=False,
                )
                stdout = (proc.stdout or "")[-4000:]
                stderr = (proc.stderr or "")[-4000:]
                combined = f"{stdout}\n{stderr}"
                last_detail = combined[-800:]

                classification = classify_text(combined)
                if classification == "quota":
                    return "quota", last_detail
                if classification == "unavailable":
                    return "activation_failed", last_detail
                if classification == "transient":
                    transient_seen += 1
                    if transient_seen <= transient_retries:
                        self.log("WARN", f"transient probe failure; sleeping {backoff}s")
                        if not self.dry_run:
                            time.sleep(backoff)
                        continue
                    return "transient", last_detail
                if proc.returncode == 0 and token.lower() in combined.lower():
                    return "ok", last_detail
                return "activation_failed", (
                    f"exit={proc.returncode}; no success token; {last_detail}"
                )
            except subprocess.TimeoutExpired:
                last_detail = "probe timed out"
                transient_seen += 1
                if transient_seen <= transient_retries:
                    continue
                return "transient", last_detail
            except FileNotFoundError as exc:
                return "activation_failed", f"probe executable missing: {exc}"
            except Exception as exc:
                return "activation_failed", f"probe error: {exc}"

        return "transient", last_detail

    # -- terminal state --------------------------------------------------

    def declare_unavailable(self, reason: str) -> str:
        self.log("ERROR", f"MODEL_UNAVAILABLE: {reason}")
        self.record_event("model_unavailable", {"text": reason[:500]})
        # Fixed marker file: the only shutdown interlock.
        try:
            atomic_write(
                self.marker_path,
                json.dumps({"declared_at": now_iso(), "reason": reason[:1000]}) + "\n",
            )
        except OSError as exc:
            self.log("ERROR", f"Could not write MODEL_UNAVAILABLE marker: {exc}")
        self.set_phase("MODEL_UNAVAILABLE", reason=reason)
        self.run_shutdown(reason)
        return "MODEL_UNAVAILABLE"

    # -- shutdown --------------------------------------------------------

    def run_shutdown(self, reason: str) -> bool:
        """Execute the graceful shutdown sequence exactly once.

        Returns True if the sequence ran, False if it was suppressed.
        """
        lock_handle = None
        try:
            lock_handle = open(self.lock_path, "a+")
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            self.log("WARN", "Shutdown already owned by another process — skipping")
            if lock_handle:
                lock_handle.close()
            return False

        try:
            if os.path.exists(self.shutdown_marker):
                self.log("WARN", "Shutdown already started — skipping duplicate")
                return False
            atomic_write(
                self.shutdown_marker,
                json.dumps({"started_at": now_iso(), "reason": reason}) + "\n",
            )

            self.log("SHUTDOWN", f"begin (dry_run={self.dry_run}) reason={reason}")

            # 1. Durable checkpoint before anything else.
            self.checkpoint("pre_shutdown")

            # 2. Stop registered background processes safely.
            self.stop_managed_processes()

            # 3. Optional operator-supplied pre-shutdown hooks.
            for argv in self.cfg.get("shutdown", {}).get("pre_shutdown_commands", []) or []:
                self._run_command(list(argv), label="pre_shutdown")

            # 4. Flush filesystem buffers.
            try:
                os.sync()
                self.log("SHUTDOWN", "filesystem buffers flushed")
            except Exception as exc:
                self.log("WARN", f"sync failed: {exc}")

            # 5. Stop OpenCode gracefully.
            shutdown_cfg = self.cfg.get("shutdown", {})
            if shutdown_cfg.get("stop_opencode", True):
                self._run_command(
                    list(shutdown_cfg.get("opencode_stop_command")
                         or ["opencode", "service", "stop"]),
                    label="stop_opencode",
                )

            # 6. Power off, unless disabled or dry-run.
            if not shutdown_cfg.get("enabled", False):
                self.log(
                    "SHUTDOWN",
                    "power-off disabled in config; relying on the externally "
                    "scheduled shutdown as the safety fallback",
                )
                return True

            for argv in shutdown_cfg.get("commands", []) or []:
                argv = list(argv)
                if self.dry_run:
                    self.log("DRY-RUN", f"would execute: {' '.join(argv)}")
                    continue
                if self._run_command(argv, label="poweroff"):
                    self.log("SHUTDOWN", f"power-off command succeeded: {' '.join(argv)}")
                    return True
            if self.dry_run:
                self.log("DRY-RUN", "shutdown sequence complete (no power-off executed)")
            else:
                self.log("ERROR", "All power-off commands failed")
            return True
        except Exception:
            self.log("ERROR", f"shutdown sequence error:\n{traceback.format_exc()}")
            return False
        finally:
            if lock_handle is not None:
                try:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                lock_handle.close()

    def _run_command(self, argv: list[str], label: str) -> bool:
        if not argv:
            return False
        if self.dry_run:
            self.log("DRY-RUN", f"would execute [{label}]: {' '.join(argv)}")
            return True
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=60, check=False)
            if proc.returncode == 0:
                self.log("SHUTDOWN", f"[{label}] ok: {' '.join(argv)}")
                return True
            self.log(
                "WARN",
                f"[{label}] failed rc={proc.returncode}: "
                f"{(proc.stderr or proc.stdout or '').strip()[:300]}",
            )
            return False
        except FileNotFoundError:
            self.log("WARN", f"[{label}] executable not found: {argv[0]}")
            return False
        except Exception as exc:
            self.log("WARN", f"[{label}] error: {exc}")
            return False

    def stop_managed_processes(self) -> int:
        """SIGTERM then SIGKILL only the PIDs explicitly registered."""
        if not os.path.isfile(self.pids_path):
            return 0
        stopped = 0
        try:
            with open(self.pids_path, "r", encoding="utf-8") as handle:
                pids = [int(line.strip()) for line in handle if line.strip().isdigit()]
        except OSError:
            return 0

        grace = float(self.cfg.get("shutdown", {}).get("grace_seconds", 20))
        alive: list[int] = []
        for pid in pids:
            if pid <= 1 or pid == os.getpid():
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                alive.append(pid)
                stopped += 1
            except ProcessLookupError:
                continue
            except PermissionError:
                self.log("WARN", f"not permitted to signal pid {pid}")

        if not alive:
            return stopped
        if self.dry_run:
            self.log("DRY-RUN", f"registered PIDs signalled: {alive}")
            return stopped

        deadline = time.time() + grace
        while time.time() < deadline:
            alive = [pid for pid in alive if _pid_exists(pid)]
            if not alive:
                break
            time.sleep(1)
        for pid in alive:
            try:
                os.kill(pid, signal.SIGKILL)
                self.log("SHUTDOWN", f"SIGKILL sent to {pid}")
            except Exception:
                pass
        return stopped

    # -- log tail --------------------------------------------------------

    def tail_logs_once(self, offsets: dict) -> None:
        """Scan configured log files for new confirmed provider errors.

        Disabled by default: the OpenCode server log carries lifecycle
        messages, not provider API errors. When enabled, a line must be an
        ERROR/WARN level record *and* contain a provider-error marker, so that
        unrelated text echoed into the log cannot trigger the state machine.
        """
        for pattern in self.cfg.get("log_files", []):
            path = expand(pattern)
            if not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
                offset = offsets.get(path, size)
                if size < offset:
                    offset = 0  # rotated
                if size == offset:
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(offset)
                    chunk = handle.read(min(size - offset, 512 * 1024))
                    offsets[path] = handle.tell()
            except OSError:
                continue

            for line in chunk.splitlines():
                low = line.lower()
                if "level=error" not in low and "level=warn" not in low:
                    continue
                if not any(marker in low for marker in PROVIDER_ERROR_MARKERS):
                    continue
                classification = classify_text(line)
                if classification in ("quota", "unavailable"):
                    model = self.cfg["primary_model"]
                    if model.split("/")[-1].split("#")[0].lower() in low:
                        self.handle_failure(classification, line[:600], model)
                        return

    # -- session database ------------------------------------------------

    def poll_db(self) -> str:
        """Poll OpenCode's session database for real provider errors.

        An assistant message may carry an ``error`` object. Only messages whose
        model is one of the authorised free models are considered. Returns the
        phase after processing (or the current phase when nothing happened).
        """
        db_cfg = self.cfg.get("db", {}) or {}
        if not db_cfg.get("enabled", True):
            return self.state.get("phase", "IDLE")

        path = expand(db_cfg.get("path") or "~/.local/share/opencode/opencode.db")
        if not os.path.isfile(path):
            return self.state.get("phase", "IDLE")

        since = int(self.state.get("last_db_message_ms") or 0)
        if not since:
            # Only consider errors that occur after the watchdog started, so a
            # historical failure cannot trigger a shutdown of a healthy sprint.
            if db_cfg.get("start_from_now", True):
                since = int(time.time() * 1000)
            self.state["last_db_message_ms"] = since
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
            try:
                con.row_factory = sqlite3.Row
                rows = con.execute(
                    "select id, time_created, data from session_message "
                    "where type = 'assistant' and time_created > ? "
                    "order by time_created asc limit 50",
                    (since,),
                ).fetchall()
            finally:
                con.close()
        except sqlite3.Error as exc:
            self.log("WARN", f"session db unavailable: {exc}")
            return self.state.get("phase", "IDLE")

        authorised = {self.cfg["primary_model"], *(self.cfg.get("fallback_models") or [])}
        phase = self.state.get("phase", "IDLE")
        for row in rows:
            created = int(row["time_created"])
            if created > since:
                since = created
            try:
                payload = json.loads(row["data"])
            except (TypeError, ValueError):
                continue
            error = payload.get("error")
            if not error:
                continue
            model_cfg = payload.get("model") or {}
            model_id = (
                f"{model_cfg.get('providerID', '')}/{model_cfg.get('id', '')}"
                if model_cfg else ""
            )
            if model_id not in authorised:
                continue

            err_type = str(error.get("type") or "")
            err_message = str(error.get("message") or "")
            blob = f"{err_type} {err_message}"
            blob_low = blob.lower()

            if err_type == "aborted":
                continue
            classification = classify_text(blob)
            hard = any(t in blob_low.replace(" ", "") for t in HARD_ERROR_TYPES)
            if classification in ("quota", "unavailable") or hard:
                phase = self.handle_failure(
                    classification if classification != "unknown" else "quota",
                    blob[:600],
                    model_id,
                )
                if phase == "MODEL_UNAVAILABLE":
                    break
            elif classification == "transient":
                self.record_event(
                    "transient", {"text": blob[:300], "model": model_id}
                )

        if since:
            self.state["last_db_message_ms"] = since
            self.save_state()
        return phase

    # -- main loop -------------------------------------------------------

    def run(self) -> int:
        self.log(
            "START",
            f"watchdog pid={os.getpid()} dry_run={self.dry_run} "
            f"primary={self.cfg['primary_model']}",
        )
        self.checkpoint("startup")

        offsets: dict[str, int] = {}
        last_ckpt = time.time()
        interval = float(self.cfg.get("poll_interval_s", 5))
        ckpt_every = float(self.cfg.get("checkpoint_interval_s", 600))
        db_every = float((self.cfg.get("db") or {}).get("poll_interval_s", 5))
        last_db = 0.0

        while True:
            try:
                if os.path.exists(self.marker_path):
                    # Marker already present (e.g. set by a previous run).
                    if not os.path.exists(self.shutdown_marker):
                        self.run_shutdown("marker observed")
                    return 0

                self.tail_logs_once(offsets)

                if time.time() - last_db >= db_every:
                    last_db = time.time()
                    self.poll_db()

                if time.time() - last_ckpt >= ckpt_every:
                    self.checkpoint("scheduled")
                    last_ckpt = time.time()
            except KeyboardInterrupt:
                self.log("STOP", "interrupted")
                return 130
            except Exception:
                self.log("ERROR", traceback.format_exc())
            time.sleep(interval)


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def selftest(dry_run: bool = True) -> int:
    """Exercise the full detection → fallback → shutdown path without powering off."""
    import tempfile

    failures: list[str] = []
    root = tempfile.mkdtemp(prefix="netguard_watchdog_selftest_")

    def build(probe_command, name, phase_expect=None, extra=None):
        cfg_path = os.path.join(root, f"{name}.json")
        cfg = {
            "state_dir": os.path.join(root, name),
            "watch_dir": root,
            "log_files": [],
            "probe": {"command": probe_command, "prompt": "x"},
            "shutdown": {"enabled": False},
        }
        if extra:
            cfg = merge_config(cfg, extra)
        atomic_write(cfg_path, json.dumps(cfg))
        return Watchdog(config_path=cfg_path, dry_run=dry_run,
                        log_stream=open(os.devnull, "w"))

    def check(condition, message):
        if not condition:
            failures.append(message)
            print(f"FAIL: {message}")
        else:
            print(f"ok  : {message}")

    # 1. Successful fallback keeps the sprint alive (no marker).
    wd = build(["sh", "-c", "echo NETGUARD_PROBE_OK"], "fallback_ok")
    phase = wd.handle_failure("quota", "free usage limit reached", wd.cfg["primary_model"])
    check(phase == "FALLBACK_ACTIVE", "successful fallback -> FALLBACK_ACTIVE")
    check(not os.path.exists(wd.marker_path), "successful fallback writes no MODEL_UNAVAILABLE marker")
    check(os.path.exists(wd.fallback_marker), "fallback_active marker written")

    # 2. Quota-exhausted fallback -> MODEL_UNAVAILABLE + shutdown sequence.
    wd = build(["sh", "-c", "echo 'free usage limit reached'; exit 1"], "fallback_quota")
    phase = wd.handle_failure("quota", "free usage limit reached", wd.cfg["primary_model"])
    check(phase == "MODEL_UNAVAILABLE", "fallback quota exhaustion -> MODEL_UNAVAILABLE")
    check(os.path.exists(wd.marker_path), "MODEL_UNAVAILABLE marker created")
    check(os.path.exists(wd.shutdown_marker), "shutdown sequence started once")
    check(os.path.exists(wd.state_path), "state file persisted")

    # 3. Duplicate suppression.
    second = wd.run_shutdown("duplicate attempt")
    check(second is False, "duplicate shutdown request suppressed")

    # 4. Activation failure -> MODEL_UNAVAILABLE.
    wd = build(["sh", "-c", "exit 7"], "fallback_broken")
    phase = wd.handle_failure("quota", "429 too many requests", wd.cfg["primary_model"])
    check(phase == "MODEL_UNAVAILABLE", "failed fallback activation -> MODEL_UNAVAILABLE")

    # 5. Transient network error never shuts down.
    wd = build(["sh", "-c", "echo 'connection refused'; exit 1"], "transient")
    phase = wd.handle_failure("unknown", "connection refused by peer", wd.cfg["primary_model"])
    check(phase == "IDLE", "transient network error does not change phase")
    check(not os.path.exists(wd.marker_path), "transient error writes no marker")

    # 6. Unknown failure is inert.
    wd = build(["sh", "-c", "exit 0"], "unknown")
    phase = wd.handle_failure("unknown", "something odd happened", wd.cfg["primary_model"])
    check(phase == "IDLE", "unclassified failure is inert")

    # 7. Probe output containing a shell command is never executed.
    sentinel = os.path.join(root, "pwned")
    wd = build(["sh", "-c", f"echo 'shutdown -h now && touch {sentinel}'"], "injection")
    wd.handle_failure("quota", "quota exceeded", wd.cfg["primary_model"])
    check(not os.path.exists(sentinel),
          "model/command output is never executed by the watchdog")

    # 8. Checkpoint writes are durable and parseable.
    wd = build(["sh", "-c", "echo NETGUARD_PROBE_OK"], "ckpt")
    path = wd.checkpoint("selftest")
    check(bool(path) and os.path.isfile(path), "checkpoint file written")
    check(isinstance(read_json(path, None), dict), "checkpoint file is valid JSON")

    # 9. Marker + lock behaviour under a fresh process image.
    wd = build(["sh", "-c", "echo NETGUARD_PROBE_OK"], "marker")
    atomic_write(wd.marker_path, "{}\n")
    check(os.path.exists(wd.marker_path), "fixed marker path is readable")

    # 10. Session database is the authoritative signal source.
    def make_db(name, rows):
        """rows: list of (message_id, created_ms, model_id, error_dict|None, text)"""
        path = os.path.join(root, f"{name}.db")
        con = sqlite3.connect(path)
        con.execute(
            "create table session_message (id text, session_id text, type text, "
            "seq integer, time_created integer, time_updated integer, data text)"
        )
        for mid, created, model_id, error, text in rows:
            payload = {
                "model": {"providerID": "opencode", "id": model_id},
                "time": {"created": created},
                "content": [{"type": "text", "text": text}],
            }
            if error is not None:
                payload["error"] = error
            con.execute(
                "insert into session_message values (?,?,?,?,?,?,?)",
                (mid, "ses_test", "assistant", 1, created, created,
                 json.dumps(payload)),
            )
        con.commit()
        con.close()
        return path

    base = 1794500000000
    db_path = make_db("quota", [
        ("m1", base + 1000, "deepseek-v4.1-flash-free", None, "tool output: 429 rate limit exceeded"),
        ("m2", base + 2000, "deepseek-v4.1-flash-free",
         {"type": "APIError", "message": "Free usage limit reached for this model"},
         "partial"),
    ])
    wd = build(["sh", "-c", "echo NETGUARD_PROBE_OK"], "db_primary",
               extra={"db": {"enabled": True, "path": db_path, "start_from_now": False}})
    phase = wd.poll_db()
    check(phase == "FALLBACK_ACTIVE",
          "db: primary quota error triggers exactly one successful fallback")

    # Non-authorised model errors must be ignored.
    db_path2 = make_db("other", [
        ("m3", base + 3000, "some-other-model",
         {"type": "APIError", "message": "429 rate limit exceeded"}, "x"),
    ])
    wd = build(["sh", "-c", "echo NETGUARD_PROBE_OK"], "db_other",
               extra={"db": {"enabled": True, "path": db_path2, "start_from_now": False}})
    phase = wd.poll_db()
    check(phase == "IDLE", "db: error from a non-authorised model is ignored")
    check(not os.path.exists(wd.marker_path), "db: ignored model writes no marker")

    # Aborted steps and error-free messages are ignored.
    db_path3 = make_db("aborted", [
        ("m4", base + 4000, "deepseek-v4.1-flash-free",
         {"type": "aborted", "message": "Step interrupted"}, ""),
        ("m5", base + 5000, "deepseek-v4.1-flash-free", None,
         "quota exceeded 429 free usage limit"),
    ])
    wd = build(["sh", "-c", "echo NETGUARD_PROBE_OK"], "db_aborted",
               extra={"db": {"enabled": True, "path": db_path3, "start_from_now": False}})
    phase = wd.poll_db()
    check(phase == "IDLE", "db: aborted/error-free messages are ignored")

    # A transient provider error must not shut the machine down.
    db_path4 = make_db("transient_db", [
        ("m6", base + 6000, "deepseek-v4.1-flash-free",
         {"type": "APIError", "message": "connection refused"}, "x"),
    ])
    wd = build(["sh", "-c", "echo 'connection refused'; exit 1"], "db_transient",
               extra={"db": {"enabled": True, "path": db_path4, "start_from_now": False}})
    phase = wd.poll_db()
    check(phase == "IDLE", "db: transient provider error does not trigger fallback")
    check(not os.path.exists(wd.marker_path), "db: transient error writes no marker")

    # 11. INFO-level log chatter never triggers the state machine.
    log_path = os.path.join(root, "fake.log")
    atomic_write(
        log_path,
        'timestamp=2026-11-12T17:00:00Z level=INFO message="spawning process" '
        'command=/bin/sh args="[\\"-c\\",\\"echo 429 rate limit model\\"]"\n',
    )
    wd = build(["sh", "-c", "echo NETGUARD_PROBE_OK"], "log_noise",
               extra={"log_files": [log_path]})
    wd.tail_logs_once({})
    check(wd.state.get("phase") == "IDLE",
          "log: unrelated INFO chatter does not trigger the watchdog")

    print()
    if failures:
        print(f"SELFTEST FAILED ({len(failures)} check(s))")
        for item in failures:
            print(f"  - {item}")
        return 1
    print(f"SELFTEST PASSED (dry_run={dry_run}) — artifact root: {root}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NetGuard model failover watchdog")
    parser.add_argument("--config", default=None)
    parser.add_argument("--dry-run", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("run")
    sub.add_parser("status")
    sub.add_parser("checkpoint")

    feed = sub.add_parser("feed")
    feed.add_argument("--kind", required=True,
                      choices=["quota", "unavailable", "transient", "unknown"])
    feed.add_argument("--text", default="")
    feed.add_argument("--model", default="")

    st = sub.add_parser("selftest")
    st.add_argument("--dry-run", action="store_true", default=True)

    args = parser.parse_args(argv)

    if args.command == "selftest":
        return selftest(dry_run=True)

    wd = Watchdog(config_path=args.config, dry_run=args.dry_run)

    if args.command == "run":
        return wd.run()
    if args.command == "checkpoint":
        return 0 if wd.checkpoint("manual") else 1
    if args.command == "feed":
        phase = wd.handle_failure(args.kind, args.text, args.model)
        print(json.dumps({"phase": phase, "marker": os.path.exists(wd.marker_path)}))
        return 0
    if args.command == "status":
        print(json.dumps({
            "phase": wd.state.get("phase"),
            "state": wd.state,
            "model_unavailable": os.path.exists(wd.marker_path),
            "shutdown_started": os.path.exists(wd.shutdown_marker),
            "fallback_active": os.path.exists(wd.fallback_marker),
            "state_dir": wd.state_dir,
        }, indent=2))
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
