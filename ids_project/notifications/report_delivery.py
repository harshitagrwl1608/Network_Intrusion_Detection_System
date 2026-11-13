"""
notifications/report_delivery.py
--------------------------------
Bridges the report generator and the durable email outbox.

Responsibilities:

* Render a report to a **bounded artifact directory** the application owns.
  Callers never supply a filesystem path.
* Validate any path used for an attachment (rejects traversal, symlinks and
  files outside the artifact root).
* Enforce an attachment size ceiling with a clear, actionable error and a safe
  alternative (download the report from the dashboard instead).
* Prune old artifacts so the directory cannot grow without bound.

No report bytes are stored in the database; the outbox row keeps only a
reference plus bounded metadata.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Keep in sync with notifications.providers.MAX_ATTACHMENT_BYTES.
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
# Retain generated artifacts for a bounded period; they exist only to bridge
# generation and asynchronous delivery.
ARTIFACT_MAX_AGE_S = 24 * 3600
ARTIFACT_MAX_FILES = 200

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class ReportDeliveryError(Exception):
    """Base class for report-email failures that should be shown to the user."""


class ReportTooLargeError(ReportDeliveryError):
    """Raised when a generated report exceeds the attachment ceiling."""


@dataclass
class ReportArtifact:
    path: str
    filename: str
    mime: str
    size_bytes: int
    sha256: str

    def as_attachment(self) -> dict:
        return {
            "path": self.path,
            "filename": self.filename,
            "mime": self.mime,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


def artifact_root() -> str:
    """Return (and create) the artifact directory owned by the application."""
    try:
        import config

        configured = os.getenv("REPORT_ARTIFACT_DIR", "")
        if configured:
            root = configured
        else:
            db_dir = os.path.dirname(os.path.abspath(getattr(config, "SQLITE_PATH", "storage/alerts.db")))
            root = os.path.join(db_dir, "report_artifacts")
    except Exception:
        root = os.path.join(tempfile.gettempdir(), "netguard_report_artifacts")

    os.makedirs(root, mode=0o700, exist_ok=True)
    return os.path.realpath(root)


def safe_filename(name: str, fallback: str = "netguard_report") -> str:
    """Reduce a generated filename to a safe basename."""
    base = os.path.basename(str(name or "").replace("\\", "/"))
    base = _SAFE_NAME_RE.sub("_", base).strip("._")
    if not base:
        base = fallback
    return base[:180]


def resolve_artifact_path(path: str) -> str:
    """Resolve and validate an attachment path against the artifact root.

    Raises ``ReportDeliveryError`` if the path escapes the root, traverses a
    symlink out of it, or does not exist.
    """
    root = artifact_root()
    candidate = str(path or "")
    if not candidate:
        raise ReportDeliveryError("Attachment reference is empty")

    # Reject NUL and control characters outright.
    if any(ord(ch) < 0x20 for ch in candidate):
        raise ReportDeliveryError("Attachment reference contains control characters")

    if not os.path.isabs(candidate):
        raise ReportDeliveryError("Attachment reference must be an absolute path")

    real = os.path.realpath(candidate)
    if real != root and not real.startswith(root + os.sep):
        raise ReportDeliveryError("Attachment reference escapes the artifact directory")

    if not os.path.isfile(real):
        raise ReportDeliveryError("Attachment file no longer exists")

    return real


def generate_artifact(generator, report_type: str, hours: int, fmt: str,
                      case_id: str | None = None) -> ReportArtifact:
    """Generate a report and persist it inside the artifact directory.

    ``generator`` is a ``reports.generator.ReportGenerator`` instance. The
    generator returns ``(mime, filename, content)``.
    """
    mime, filename, content = generator.generate(
        report_type=report_type, hours=hours, fmt=fmt, case_id=case_id
    )

    if isinstance(content, str):
        data = content.encode("utf-8")
    elif isinstance(content, (bytes, bytearray)):
        data = bytes(content)
    else:
        raise ReportDeliveryError("Report generator returned an unsupported payload type")

    if len(data) > MAX_ATTACHMENT_BYTES:
        raise ReportTooLargeError(
            f"Report is {len(data) / (1024 * 1024):.1f} MiB, which exceeds the "
            f"{MAX_ATTACHMENT_BYTES // (1024 * 1024)} MiB email attachment limit. "
            "Use 'Generate & Download' to retrieve it locally, or narrow the "
            "report time window."
        )

    root = artifact_root()
    safe_name = safe_filename(filename)
    unique = f"{int(time.time() * 1000)}_{os.getpid()}_{next(tempfile._get_candidate_names())[:8]}"
    final_name = f"{unique}_{safe_name}"
    path = os.path.join(root, final_name)

    # Write atomically so a concurrent sender never reads a partial file.
    fd, tmp_path = tempfile.mkstemp(dir=root, prefix=".tmp_report_")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    digest = hashlib.sha256(data).hexdigest()
    return ReportArtifact(
        path=os.path.realpath(path),
        filename=safe_name,
        mime=str(mime or "application/octet-stream"),
        size_bytes=len(data),
        sha256=digest,
    )


def prune_artifacts(max_age_s: int = ARTIFACT_MAX_AGE_S,
                    max_files: int = ARTIFACT_MAX_FILES) -> int:
    """Delete stale artifacts. Returns the number of files removed."""
    try:
        root = artifact_root()
    except Exception:
        return 0

    removed = 0
    now = time.time()
    entries: list[tuple[float, str]] = []
    try:
        for name in os.listdir(root):
            full = os.path.join(root, name)
            if not os.path.isfile(full):
                continue
            try:
                mtime = os.path.getmtime(full)
            except OSError:
                continue
            entries.append((mtime, full))
    except OSError:
        return 0

    for mtime, full in entries:
        if now - mtime > max_age_s:
            try:
                os.unlink(full)
                removed += 1
            except OSError:
                pass

    survivors = [(m, f) for (m, f) in entries if os.path.exists(f)]
    if len(survivors) > max_files:
        survivors.sort()
        for _, full in survivors[: len(survivors) - max_files]:
            try:
                os.unlink(full)
                removed += 1
            except OSError:
                pass

    return removed


def build_report_payload(artifact: ReportArtifact, *, report_title: str,
                         report_type: str, fmt: str, hours: int,
                         generated_at: str | None = None,
                         summary_rows: list[tuple[str, Any]] | None = None) -> dict:
    """Build the bounded JSON payload stored on the outbox row."""
    return {
        "kind": "report",
        "report": {
            "title": str(report_title or "NetGuard IDS Report")[:200],
            "type": str(report_type)[:40],
            "format": str(fmt)[:10],
            "hours": int(hours),
            "generated_at": str(generated_at or time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))[:40],
            "summary_rows": [[str(k)[:80], str(v)[:300]] for k, v in (summary_rows or [])][:20],
        },
        "attachment": artifact.as_attachment(),
    }


def dump_payload(payload: dict) -> str:
    """Serialise a payload defensively; never fails the caller on odd objects."""
    try:
        return json.dumps(payload, default=str)[:65536]
    except Exception:
        return json.dumps({"kind": "unknown"})
