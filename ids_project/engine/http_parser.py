"""
NetGuard IDS — Bounded Deterministic HTTP/1.x Parsing Layer
==========================================================
Provides application-layer context separation (Request vs. Response, Target,
Query Parameters, Headers, Form/Body) for Deep Packet Inspection (DPI).

Designed to:
- Dissect cleartext HTTP/1.x requests and responses deterministically.
- Extract request method, URI path, query parameters, headers, and bodies.
- Handle Content-Length and chunked transfer decoding with bounded buffers.
- Parse form-urlencoded and multipart form data while stripping boundary artifacts.
- Distinguish client requests from server responses to prevent response reflection FPs.
- Support non-HTTP protocol routing (databases, mail, command services, ICS).
"""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import unquote_to_bytes


class HttpDirection(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    AMBIGUOUS = "ambiguous"
    NON_HTTP = "non_http"


class InspectionContext(str, Enum):
    HTTP_REQUEST_LINE = "http_request_line"
    HTTP_REQUEST_PATH = "http_request_path"
    HTTP_QUERY_PARAM = "http_query_param"
    HTTP_REQUEST_HEADER = "http_request_header"
    HTTP_REQUEST_BODY = "http_request_body"
    HTTP_RESPONSE_LINE = "http_response_line"
    HTTP_RESPONSE_HEADER = "http_response_header"
    HTTP_RESPONSE_BODY = "http_response_body"
    RAW_STREAM = "raw_stream"
    DB_PAYLOAD = "db_payload"
    MAIL_PAYLOAD = "mail_payload"
    COMMAND_SERVICE = "command_service"
    ICS_PAYLOAD = "ics_payload"


# Standard known service port sets
HTTP_PORTS: set[int] = {
    80, 8080, 3000, 5000, 8000, 8888, 9000, 4848, 8161, 2375, 6443, 9090, 7547
}
DB_PORTS: set[int] = {1433, 3306, 5432, 27017, 9200}
MAIL_PORTS: set[int] = {25, 587, 110, 143}
CMD_PORTS: set[int] = {21, 23, 6379, 11211, 61616, 8291}
ICS_PORTS: set[int] = {1502}

# Compiled matchers for HTTP/1.x framing
_REQ_LINE_RE = re.compile(
    rb"(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE|TRACK|DEBUG|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|SEARCH)\s+(?:(.+?)\s+HTTP/(1\.[01]|2\.0|0\.9)|([^\r\n]+))(?:\r?\n|$)"
)
_RESP_LINE_RE = re.compile(
    rb"^HTTP/(1\.[01]|2\.0)\s+([1-5]\d{2})(?:\s+([^\r\n]*))?(?:\r?\n|$)"
)


@dataclass
class HttpMessage:
    direction: HttpDirection
    method: Optional[bytes] = None
    target: Optional[bytes] = None
    path: Optional[bytes] = None
    query_string: Optional[bytes] = None
    query_params: List[Tuple[bytes, bytes]] = field(default_factory=list)
    status_code: Optional[int] = None
    status_phrase: Optional[bytes] = None
    headers: List[Tuple[bytes, bytes]] = field(default_factory=list)
    header_map: Dict[bytes, bytes] = field(default_factory=dict)
    body: bytes = b""
    form_params: List[Tuple[bytes, bytes]] = field(default_factory=list)
    is_chunked: bool = False
    content_type: Optional[bytes] = None
    content_length: Optional[int] = None
    raw_sample: bytes = b""


class HttpParser:
    """Bounded, deterministic HTTP/1.x parser for application-aware DPI."""

    @staticmethod
    def parse(payload: bytes, src_port: int = 0, dst_port: int = 0) -> HttpMessage:
        """Parse payload bytes into a structured HttpMessage with direction and components."""
        if not payload:
            return HttpMessage(direction=HttpDirection.NON_HTTP, raw_sample=payload)

        # 1. Try matching HTTP Request line
        req_match = _REQ_LINE_RE.match(payload)
        if req_match:
            target = (req_match.group(2) or req_match.group(4) or b"").strip()
            has_http_version = bool(req_match.group(3))
            is_valid_target = target.startswith((b"/", b"*", b"http://", b"https://")) or has_http_version
            if is_valid_target:
                method = req_match.group(1).upper()
                line_end = req_match.end()

                path = target
                query_string = None
                query_params: List[Tuple[bytes, bytes]] = []
                if b"?" in target:
                    path, query_string = target.split(b"?", 1)
                    for pair in re.split(rb"[&;]", query_string):
                        if not pair:
                            continue
                        if b"=" in pair:
                            k, v = pair.split(b"=", 1)
                            query_params.append((k, v))
                        else:
                            query_params.append((pair, b""))

                headers, header_map, body = HttpParser._parse_headers_and_body(payload[line_end:])
                content_type = header_map.get(b"content-type")
                content_length = None
                if b"content-length" in header_map:
                    try:
                        content_length = int(header_map[b"content-length"])
                    except Exception:
                        content_length = None

                is_chunked = b"chunked" in header_map.get(b"transfer-encoding", b"").lower()
                if is_chunked and body:
                    body = HttpParser._dechunk(body)

                form_params = HttpParser._parse_form_params(body, content_type)

                return HttpMessage(
                    direction=HttpDirection.REQUEST,
                    method=method,
                    target=target,
                    path=path,
                    query_string=query_string,
                    query_params=query_params,
                    headers=headers,
                    header_map=header_map,
                    body=body,
                    form_params=form_params,
                    is_chunked=is_chunked,
                    content_type=content_type,
                    content_length=content_length,
                    raw_sample=payload,
                )

        # 2. Try matching HTTP Response line
        resp_match = _RESP_LINE_RE.match(payload)
        if resp_match:
            status_code = int(resp_match.group(2))
            status_phrase = resp_match.group(3)
            line_end = resp_match.end()

            headers, header_map, body = HttpParser._parse_headers_and_body(payload[line_end:])
            content_type = header_map.get(b"content-type")
            content_length = None
            if b"content-length" in header_map:
                try:
                    content_length = int(header_map[b"content-length"])
                except Exception:
                    content_length = None

            is_chunked = b"chunked" in header_map.get(b"transfer-encoding", b"").lower()
            if is_chunked and body:
                body = HttpParser._dechunk(body)

            return HttpMessage(
                direction=HttpDirection.RESPONSE,
                status_code=status_code,
                status_phrase=status_phrase,
                headers=headers,
                header_map=header_map,
                body=body,
                is_chunked=is_chunked,
                content_type=content_type,
                content_length=content_length,
                raw_sample=payload,
            )

        # Non-HTTP protocol service context when not cleartext HTTP request/response
        if dst_port in DB_PORTS or src_port in DB_PORTS:
            return HttpMessage(direction=HttpDirection.NON_HTTP, raw_sample=payload)
        if dst_port in MAIL_PORTS or src_port in MAIL_PORTS:
            return HttpMessage(direction=HttpDirection.NON_HTTP, raw_sample=payload)
        if dst_port in CMD_PORTS or src_port in CMD_PORTS:
            return HttpMessage(direction=HttpDirection.NON_HTTP, raw_sample=payload)
        if dst_port in ICS_PORTS or src_port in ICS_PORTS:
            return HttpMessage(direction=HttpDirection.NON_HTTP, raw_sample=payload)

        # 3. Not beginning with formal request or response line
        # If port indicates server response (source port is HTTP, destination is ephemeral):
        if src_port in HTTP_PORTS and dst_port not in HTTP_PORTS:
            return HttpMessage(direction=HttpDirection.RESPONSE, body=payload, raw_sample=payload)

        # If destination port is HTTP, but header line was missing or partial:
        if dst_port in HTTP_PORTS:
            return HttpMessage(direction=HttpDirection.AMBIGUOUS, body=payload, raw_sample=payload)

        return HttpMessage(direction=HttpDirection.NON_HTTP, raw_sample=payload)

    @staticmethod
    def _parse_headers_and_body(data: bytes) -> Tuple[List[Tuple[bytes, bytes]], Dict[bytes, bytes], bytes]:
        """Bounded extraction of HTTP headers and body."""
        headers: List[Tuple[bytes, bytes]] = []
        header_map: Dict[bytes, bytes] = {}
        body = b""

        # Bounded search for header boundary (max 8192 bytes for header block)
        header_limit = min(len(data), 8192)
        header_end = data.find(b"\r\n\r\n", 0, header_limit)
        delimiter_len = 4
        if header_end == -1:
            header_end = data.find(b"\n\n", 0, header_limit)
            delimiter_len = 2

        if header_end != -1:
            header_bytes = data[:header_end]
            body = data[header_end + delimiter_len:]
        else:
            header_bytes = data[:header_limit]
            body = b""

        for line in header_bytes.splitlines():
            line = line.strip()
            if not line:
                continue
            if b":" in line:
                name, val = line.split(b":", 1)
                name = name.strip()
                val = val.strip()
                headers.append((name, val))
                header_map[name.lower()] = val

        return headers, header_map, body

    @staticmethod
    def _dechunk(data: bytes, max_bytes: int = 4096) -> bytes:
        """Decode chunked transfer encoding safely within bounded memory."""
        out = bytearray()
        pos = 0
        while pos < len(data) and len(out) < max_bytes:
            crlf = data.find(b"\r\n", pos)
            if crlf == -1:
                out.extend(data[pos:])
                break
            line = data[pos:crlf].strip()
            if not line:
                pos = crlf + 2
                continue
            try:
                chunk_len = int(line.split(b";")[0], 16)
            except Exception:
                out.extend(data[pos:])
                break
            if chunk_len == 0:
                break
            chunk_start = crlf + 2
            chunk_end = chunk_start + chunk_len
            out.extend(data[chunk_start:min(chunk_end, len(data))])
            pos = chunk_end + 2
        return bytes(out)

    @staticmethod
    def _parse_form_params(body: bytes, content_type: Optional[bytes]) -> List[Tuple[bytes, bytes]]:
        """Extract user-controlled parameter values, stripping boundary delimiters."""
        params: List[Tuple[bytes, bytes]] = []
        if not body:
            return params

        ct = (content_type or b"").lower()

        # URL-encoded forms
        if b"application/x-www-form-urlencoded" in ct or (b"=" in body and b"&" in body and not ct):
            for pair in re.split(rb"[&;]", body):
                if not pair:
                    continue
                if b"=" in pair:
                    k, v = pair.split(b"=", 1)
                    params.append((k, v))
                else:
                    params.append((pair, b""))

        # Multipart form data
        elif b"multipart/form-data" in ct:
            m = re.search(rb"boundary=[\x27\x22]?([^\s;\x27\x22]+)", ct)
            if m:
                boundary = m.group(1)
                delimiter = b"--" + boundary
                parts = body.split(delimiter)
                for part in parts:
                    part = part.strip()
                    if not part or part == b"--":
                        continue
                    if b"\r\n\r\n" in part:
                        p_headers, p_body = part.split(b"\r\n\r\n", 1)
                    elif b"\n\n" in part:
                        p_headers, p_body = part.split(b"\n\n", 1)
                    else:
                        continue
                    p_body = p_body.rstrip(b"\r\n-")
                    name_m = re.search(rb'name=[\x27\x22]?([^\s;\x27\x22]+)', p_headers)
                    name = name_m.group(1) if name_m else b"part"
                    params.append((name, p_body))

        return params


def redact_sensitive_evidence(signature: str, matched: str) -> str:
    """
    Scrub sensitive credentials (passwords, bearer tokens, API keys) from alert evidence.
    Preserves diagnostic context without exposing plaintext secrets.
    """
    if signature != "CREDENTIAL_LEAK":
        return matched

    patterns = [
        (r"(?i)(password=)[^&\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(passwd=)[^&\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(\bpwd=)[^&\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(client_secret=)[^&\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(private_key=)[^&\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(api_key=)[^&\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(secret=)[^&\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(X-API-Key:\s*)[^\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(Authorization:\s*Basic\s+)[^\r\n]+", r"\1[REDACTED]"),
        (r"(?i)(Bearer\s+)[^\r\n]+", r"\1[REDACTED]"),
    ]
    result = matched
    for pat, repl in patterns:
        result = re.sub(pat, repl, result)
    return result
