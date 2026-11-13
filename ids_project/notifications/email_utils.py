"""
notifications/email_utils.py
----------------------------
Recipient list parsing, validation, and address-formatting helpers used by the
SMTP notification provider and the report-email workflow.

Security properties:

* Header injection is impossible: any address containing CR, LF, NUL or other
  control characters is rejected before a message is built.
* Recipients are de-duplicated case-insensitively while preserving the original
  spelling of the first occurrence.
* Recipient counts are capped so a single alert cannot fan out unboundedly.
* A single failing address is reported back to the caller rather than silently
  dropped, and the caller can distinguish partial from total rejection.
"""

from __future__ import annotations

import re
from email.utils import formataddr, parseaddr
from typing import Iterable

# Local-part / domain validation. Deliberately pragmatic rather than RFC-perfect:
# the SMTP server remains the final authority, but this rejects obvious junk and
# everything that could be used for header injection.
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

# Characters that must never reach a mail header.
_FORBIDDEN_CHARS = set("\r\n\x00\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")

# A hard ceiling on how many addresses a single notification may target.
MAX_RECIPIENTS_PER_FIELD = 25
MAX_TOTAL_RECIPIENTS = 50

# Addresses longer than this are not legitimate and are almost certainly an
# attempt to overflow a header or a broken paste.
MAX_ADDRESS_LENGTH = 254


class RecipientError(ValueError):
    """Raised when a recipient field cannot be parsed safely."""


def split_recipient_string(raw: str | Iterable[str] | None) -> list[str]:
    """Split a recipient field into candidate address strings.

    Accepts a single string using comma, semicolon, or newline separators, or an
    already-iterable collection of strings. Empty entries are discarded.
    """
    if raw is None:
        return []

    if isinstance(raw, (list, tuple, set, frozenset)):
        chunks: list[str] = []
        for item in raw:
            chunks.extend(split_recipient_string(item))
        return chunks

    text = str(raw)
    if not text:
        return []

    # Normalise unicode line separators, then split on every supported delimiter.
    for ch in ("\r\n", "\r", "\u2028", "\u2029", "\n"):
        text = text.replace(ch, ",")
    text = text.replace(";", ",")

    out: list[str] = []
    for part in text.split(","):
        part = part.strip()
        if part:
            out.append(part)
    return out


def _normalise_one(candidate: str) -> str:
    """Validate and normalise a single address, raising RecipientError."""
    if any(ch in _FORBIDDEN_CHARS for ch in candidate):
        raise RecipientError("address contains control characters")

    if len(candidate) > MAX_ADDRESS_LENGTH:
        raise RecipientError("address exceeds maximum length")

    # Tolerate `Display Name <user@example.com>` and extract the bare address.
    if "<" in candidate or '"' in candidate:
        _, parsed = parseaddr(candidate)
        if not parsed:
            raise RecipientError("malformed display-name address")
        candidate = parsed

    candidate = candidate.strip().strip("<>").strip()
    if not candidate:
        raise RecipientError("empty address")
    if "@" not in candidate:
        raise RecipientError("missing @ in address")
    if candidate.count("@") != 1:
        raise RecipientError("multiple @ in address")
    if not _EMAIL_RE.match(candidate):
        raise RecipientError("invalid email address syntax")

    return candidate


def parse_recipients(raw: str | Iterable[str] | None,
                     field: str = "to",
                     max_count: int = MAX_RECIPIENTS_PER_FIELD) -> tuple[list[str], list[str]]:
    """Parse, validate, and de-duplicate a recipient field.

    Returns ``(valid_addresses, invalid_entries)``. The caller decides whether
    invalid entries are fatal. Never raises for malformed *input*; only truly
    ambiguous programming errors propagate.
    """
    candidates = split_recipient_string(raw)
    valid: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()

    for candidate in candidates:
        try:
            address = _normalise_one(candidate)
        except RecipientError:
            # Never echo the raw value back into an error message unescaped; the
            # caller is responsible for safe rendering. Just record it.
            invalid.append(candidate)
            continue

        key = address.lower()
        if key in seen:
            continue
        seen.add(key)
        valid.append(address)

    if len(valid) > max_count:
        # Truncation beyond the cap is treated as a rejected recipient so the
        # operator gets a visible diagnostic rather than a silent drop.
        overflow = valid[max_count:]
        invalid.extend(overflow)
        valid = valid[:max_count]

    return valid, invalid


def parse_all_recipients(to_raw=None, cc_raw=None, bcc_raw=None) -> dict:
    """Parse To/Cc/Bcc fields and enforce the global recipient ceiling.

    Returns a dict with ``to``, ``cc``, ``bcc`` (lists), ``invalid`` (list of
    dicts), and ``errors`` (list of human-readable strings that must block
    delivery).
    """
    to_list, to_invalid = parse_recipients(to_raw, "to")
    cc_list, cc_invalid = parse_recipients(cc_raw, "cc")
    bcc_list, bcc_invalid = parse_recipients(bcc_raw, "bcc")

    errors: list[str] = []
    invalid: list[dict] = []

    for entry in to_invalid:
        invalid.append({"field": "to", "value": entry})
    for entry in cc_invalid:
        invalid.append({"field": "cc", "value": entry})
    for entry in bcc_invalid:
        invalid.append({"field": "bcc", "value": entry})

    if not to_list:
        errors.append("At least one valid 'To' recipient is required.")

    total = len(to_list) + len(cc_list) + len(bcc_list)
    if total > MAX_TOTAL_RECIPIENTS:
        errors.append(
            f"Too many recipients: {total} provided, maximum is {MAX_TOTAL_RECIPIENTS}."
        )

    return {
        "to": to_list,
        "cc": cc_list,
        "bcc": bcc_list,
        "invalid": invalid,
        "errors": errors,
    }


def format_sender(from_addr: str, from_name: str = "") -> str:
    """Format a ``From:`` header value with optional display name.

    Display names are stripped of control characters so they cannot inject
    headers. Non-ASCII names are RFC 2047 encoded by ``formataddr``.
    """
    clean_addr = str(from_addr or "").strip()
    if any(ch in _FORBIDDEN_CHARS for ch in clean_addr):
        raise RecipientError("sender address contains control characters")

    clean_name = str(from_name or "")
    clean_name = "".join(ch for ch in clean_name if ch not in _FORBIDDEN_CHARS)
    clean_name = " ".join(clean_name.split()).strip()

    if not clean_name:
        return clean_addr
    return formataddr((clean_name, clean_addr))


def redact_address(address: str) -> str:
    """Mask an address for logs/diagnostics: ``ali***@example.com``."""
    address = str(address or "")
    if "@" not in address:
        return "***"
    local, _, domain = address.partition("@")
    if len(local) <= 3:
        masked = local[:1] + "***"
    else:
        masked = local[:3] + "***"
    return f"{masked}@{domain}"
