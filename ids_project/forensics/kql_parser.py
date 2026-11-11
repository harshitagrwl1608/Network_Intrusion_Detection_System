"""
ids_project/forensics/kql_parser.py
-----------------------------------
Safe, parameterized Kibana Query Language (KQL) inspired search engine for NetGuard IDS.

Supports:
- Fields: src_ip, dst_ip, src_port, dst_port, protocol, direction, flow_id,
          alerted, alert_count, rule_name, severity, timestamp, duration,
          packet_count, byte_count, dns_query, http_host, http_uri, tls_sni,
          src_mac, dst_mac, hostname
- Operators: :, ==, !=, >, >=, <, <=, contains, startswith, in, exists
- Boolean Logic: AND, OR, NOT, Parentheses ()
- Literals: Quoted strings, numbers, booleans, IPv4/IPv6, CIDR blocks
- Parameterized SQL translation for SQLite (?) and PostgreSQL (%s)
- Deterministic natural-intent query generation assistant
"""

import re
import ipaddress
import time
from typing import Any, Tuple, List, Optional, Union


# ---------------------------------------------------------------------------
# Whitelisted Fields & Configuration
# ---------------------------------------------------------------------------

WHITELISTED_FIELDS = {
    "src_ip": {"type": "ip", "column": "src_ip"},
    "dst_ip": {"type": "ip", "column": "dst_ip"},
    "src_port": {"type": "port", "column": "src_port"},
    "dst_port": {"type": "port", "column": "dst_port"},
    "protocol": {"type": "string", "column": "protocol"},
    "direction": {"type": "string", "column": "direction"},
    "flow_id": {"type": "string", "column": "flow_id"},
    "alerted": {"type": "bool", "column": "alert_count"},
    "is_alerted": {"type": "bool", "column": "alert_count"},
    "alert_count": {"type": "int", "column": "alert_count"},
    "rule_name": {"type": "alert_field", "column": "rule_name"},
    "severity": {"type": "alert_field", "column": "severity"},
    "timestamp": {"type": "time", "column": "last_seen"},
    "duration": {"type": "float", "column": "duration_s"},
    "packet_count": {"type": "int", "column": "packet_count"},
    "byte_count": {"type": "int", "column": "byte_count"},
    "dns_query": {"type": "event_field", "column": "dns_query"},
    "http_host": {"type": "event_field", "column": "http_host"},
    "http_uri": {"type": "event_field", "column": "http_uri"},
    "tls_sni": {"type": "event_field", "column": "tls_sni"},
    "src_mac": {"type": "mac", "column": "src_mac"},
    "dst_mac": {"type": "mac", "column": "dst_mac"},
    "hostname": {"type": "string", "column": "hostname"},
}

VALID_OPERATORS = {
    ":", "==", "!=", ">", ">=", "<", "<=", "contains", "startswith", "in", "exists"
}


# ---------------------------------------------------------------------------
# Lexer / Tokenizer
# ---------------------------------------------------------------------------

class KqlToken:
    def __init__(self, type_: str, value: Any, pos: int):
        self.type = type_
        self.value = value
        self.pos = pos

    def __repr__(self):
        return f"Token({self.type}, {repr(self.value)}, pos={self.pos})"


class KqlLexer:
    """Tokenizes KQL input into a stream of tokens."""

    TOKEN_SPEC = [
        ("SKIP", r"[ \t\r\n]+"),
        ("LPAREN", r"\("),
        ("RPAREN", r"\)"),
        ("LBRACKET", r"\["),
        ("RBRACKET", r"\]"),
        ("COMMA", r","),
        ("GE", r">="),
        ("LE", r"<="),
        ("NE", r"!="),
        ("EQ", r"=="),
        ("COLON", r":"),
        ("GT", r">"),
        ("LT", r"<"),
        ("STRING_QUOTED", r'"([^"\\]|\\.)*"|\'([^\'\\]|\\.)*\''),
        ("NUMBER", r"-?\d+(\.\d+)?\b"),
        ("WORD", r"[a-zA-Z0-9_\.:\/\-]+"),
    ]

    MASTER_REGEX = re.compile("|".join(f"(?P<{pair[0]}>{pair[1]})" for pair in TOKEN_SPEC))

    KEYWORDS = {
        "and": "AND",
        "or": "OR",
        "not": "NOT",
        "contains": "CONTAINS",
        "startswith": "STARTSWITH",
        "in": "IN",
        "exists": "EXISTS",
        "true": "TRUE",
        "false": "FALSE",
        "null": "NULL",
    }

    def __init__(self, text: str):
        self.text = text
        self.tokens: List[KqlToken] = []
        self._tokenize()

    def tokenize(self) -> List[KqlToken]:
        return self.tokens

    def _tokenize(self):
        for m in self.MASTER_REGEX.finditer(self.text):
            kind = m.lastgroup
            val = m.group()
            pos = m.start()

            if kind == "SKIP":
                continue
            elif kind == "STRING_QUOTED":
                unquoted = val[1:-1].replace(r'\"', '"').replace(r"\'", "'")
                self.tokens.append(KqlToken("STRING", unquoted, pos))
            elif kind == "NUMBER":
                if "." in val:
                    self.tokens.append(KqlToken("FLOAT", float(val), pos))
                else:
                    self.tokens.append(KqlToken("INT", int(val), pos))
            elif kind == "WORD":
                lower = val.lower()
                if lower in self.KEYWORDS:
                    self.tokens.append(KqlToken(self.KEYWORDS[lower], val, pos))
                else:
                    self.tokens.append(KqlToken("IDENT", val, pos))
            else:
                self.tokens.append(KqlToken(kind, val, pos))

        self.tokens.append(KqlToken("EOF", None, len(self.text)))


# ---------------------------------------------------------------------------
# AST Nodes
# ---------------------------------------------------------------------------

class ASTNode:
    pass


class ComparisonNode(ASTNode):
    def __init__(self, field: str, op: str, value: Any):
        self.field = field
        self.op = op
        self.value = value

    def __repr__(self):
        return f"Comparison({self.field} {self.op} {repr(self.value)})"


class InNode(ASTNode):
    def __init__(self, field: str, values: List[Any]):
        self.field = field
        self.values = values

    def __repr__(self):
        return f"InNode({self.field} IN {self.values})"


class ExistsNode(ASTNode):
    def __init__(self, field: str):
        self.field = field

    def __repr__(self):
        return f"ExistsNode({self.field})"


class LogicalNode(ASTNode):
    def __init__(self, op: str, left: ASTNode, right: ASTNode):
        self.op = op.upper()  # AND or OR
        self.left = left
        self.right = right

    def __repr__(self):
        return f"Logical({self.left} {self.op} {self.right})"


class NotNode(ASTNode):
    def __init__(self, operand: ASTNode):
        self.operand = operand

    def __repr__(self):
        return f"Not({self.operand})"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class KqlParseError(ValueError):
    def __init__(self, message: str, pos: Optional[int] = None):
        super().__init__(message)
        self.pos = pos


class KqlParser:
    """
    Parses token stream into an Abstract Syntax Tree (AST).
    Precedence:
        OR (lowest)
        AND
        NOT
        Comparison / Exists / In / Parens (highest)
    """

    def __init__(self, tokens: Union[List[KqlToken], str]):
        if isinstance(tokens, str):
            tokens = KqlLexer(tokens).tokens
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> KqlToken:
        return self.tokens[self.pos]

    def consume(self, expected_type: Optional[str] = None) -> KqlToken:
        tok = self.peek()
        if expected_type and tok.type != expected_type:
            raise KqlParseError(
                f"Expected token {expected_type} but got {tok.type} ('{tok.value}')",
                tok.pos
            )
        self.pos += 1
        return tok

    def parse(self) -> Optional[ASTNode]:
        if self.peek().type == "EOF":
            return None
        node = self.parse_or()
        if self.peek().type != "EOF":
            tok = self.peek()
            raise KqlParseError(f"Unexpected token '{tok.value}' at column {tok.pos}", tok.pos)
        return node

    def parse_or(self) -> ASTNode:
        left = self.parse_and()
        while self.peek().type == "OR":
            self.consume("OR")
            right = self.parse_and()
            left = LogicalNode("OR", left, right)
        return left

    def parse_and(self) -> ASTNode:
        left = self.parse_not()
        while self.peek().type == "AND":
            self.consume("AND")
            right = self.parse_not()
            left = LogicalNode("AND", left, right)
        return left

    def parse_not(self) -> ASTNode:
        if self.peek().type == "NOT":
            self.consume("NOT")
            operand = self.parse_not()
            return NotNode(operand)
        return self.parse_primary()

    def parse_primary(self) -> ASTNode:
        tok = self.peek()
        if tok.type == "LPAREN":
            self.consume("LPAREN")
            node = self.parse_or()
            self.consume("RPAREN")
            return node

        if tok.type in ("IDENT", "STRING"):
            field = self.consume().value
            field_name = str(field).lower()

            # Check if operator follows
            next_tok = self.peek()

            if next_tok.type == "EXISTS":
                self.consume("EXISTS")
                return ExistsNode(field_name)

            if next_tok.type == "IN":
                self.consume("IN")
                values = self.parse_value_list()
                return InNode(field_name, values)

            op_map = {
                "COLON": ":",
                "EQ": "==",
                "NE": "!=",
                "GT": ">",
                "GE": ">=",
                "LT": "<",
                "LE": "<=",
                "CONTAINS": "contains",
                "STARTSWITH": "startswith",
            }

            if next_tok.type in op_map:
                op = op_map[next_tok.type]
                self.consume()
                val_tok = self.peek()
                if val_tok.type in ("IDENT", "STRING", "INT", "FLOAT", "TRUE", "FALSE", "NULL"):
                    val = self.consume().value
                    if val_tok.type == "TRUE":
                        val = True
                    elif val_tok.type == "FALSE":
                        val = False
                    elif val_tok.type == "NULL":
                        val = None
                    return ComparisonNode(field_name, op, val)
                elif val_tok.type == "LBRACKET":
                    # Array comparison e.g. field : [val1, val2] treated as IN
                    vals = self.parse_value_list()
                    return InNode(field_name, vals)
                else:
                    raise KqlParseError(f"Expected value after operator '{op}' at column {val_tok.pos}", val_tok.pos)

            # Bare term / default field search (fallback: treat as general search over IP/protocol/rule)
            return ComparisonNode("general", ":", field)

        raise KqlParseError(f"Unexpected token {tok.type} ('{tok.value}') at column {tok.pos}", tok.pos)

    def parse_value_list(self) -> List[Any]:
        self.consume("LBRACKET")
        vals = []
        while self.peek().type != "RBRACKET":
            tok = self.consume()
            if tok.type in ("IDENT", "STRING", "INT", "FLOAT"):
                vals.append(tok.value)
            if self.peek().type == "COMMA":
                self.consume("COMMA")
        self.consume("RBRACKET")
        return vals


# ---------------------------------------------------------------------------
# Validator & Parameterized SQL Generator
# ---------------------------------------------------------------------------

class KqlCompiler:
    """Validates AST and compiles into safe parameterized SQL."""

    def __init__(self, backend: str = "sqlite"):
        self.backend = backend.lower()
        self.param_placeholder = "%s" if self.backend == "postgres" else "?"
        self.params: List[Any] = []

    def compile(self, node: Optional[ASTNode]) -> Tuple[str, List[Any]]:
        self.params = []
        if node is None:
            return "1=1", []
        sql = self._visit(node)
        return sql, self.params

    def _visit(self, node: ASTNode) -> str:
        if isinstance(node, LogicalNode):
            left_sql = self._visit(node.left)
            right_sql = self._visit(node.right)
            return f"({left_sql} {node.op} {right_sql})"

        if isinstance(node, NotNode):
            operand_sql = self._visit(node.operand)
            return f"(NOT {operand_sql})"

        if isinstance(node, ExistsNode):
            field = self._validate_field(node.field)
            col = WHITELISTED_FIELDS[field]["column"]
            return f"({col} IS NOT NULL AND {col} != '')"

        if isinstance(node, InNode):
            field = self._validate_field(node.field)
            col = WHITELISTED_FIELDS[field]["column"]
            if not node.values:
                return "1=0"
            placeholders = ", ".join([self.param_placeholder] * len(node.values))
            for v in node.values:
                self.params.append(self._validate_value(field, v))
            return f"{col} IN ({placeholders})"

        if isinstance(node, ComparisonNode):
            return self._compile_comparison(node)

        raise KqlParseError(f"Unsupported AST node: {type(node)}")

    def _validate_field(self, field: str) -> str:
        f_lower = field.lower()
        if f_lower == "general":
            return "general"
        if f_lower not in WHITELISTED_FIELDS:
            valid_list = ", ".join(sorted(WHITELISTED_FIELDS.keys()))
            raise KqlParseError(f"Unknown field '{field}'. Valid fields are: {valid_list}")
        return f_lower

    def _validate_value(self, field: str, value: Any) -> Any:
        if field == "general":
            return str(value)
        meta = WHITELISTED_FIELDS[field]
        ftype = meta["type"]

        if ftype == "port":
            try:
                p = int(value)
                if not (1 <= p <= 65535):
                    raise ValueError()
                return p
            except Exception:
                raise KqlParseError(f"Field '{field}' must be a valid port integer between 1 and 65535 (got {value})")

        if ftype == "int":
            try:
                return int(value)
            except Exception:
                raise KqlParseError(f"Field '{field}' must be an integer (got {value})")

        if ftype == "float":
            try:
                return float(value)
            except Exception:
                raise KqlParseError(f"Field '{field}' must be a number (got {value})")

        if ftype == "bool":
            if isinstance(value, bool):
                return value
            if str(value).lower() in ("true", "1", "yes"):
                return True
            if str(value).lower() in ("false", "0", "no"):
                return False
            raise KqlParseError(f"Field '{field}' must be true or false (got {value})")

        if ftype == "ip":
            val_str = str(value).strip()
            # Allow CIDR or single IP
            try:
                if "/" in val_str:
                    ipaddress.ip_network(val_str, strict=False)
                    return val_str
                else:
                    ipaddress.ip_address(val_str)
                    return val_str
            except ValueError:
                # If not a strict IP, allow prefix/substring if operator is contains/startswith
                return val_str

        return str(value)

    def _compile_comparison(self, node: ComparisonNode) -> str:
        field = self._validate_field(node.field)
        op = node.op
        val = node.value

        # General search fallback
        if field == "general":
            p = f"%{val}%"
            self.params.extend([p, p, p, p])
            return f"(src_ip LIKE {self.param_placeholder} OR dst_ip LIKE {self.param_placeholder} OR protocol LIKE {self.param_placeholder} OR flow_id LIKE {self.param_placeholder})"

        meta = WHITELISTED_FIELDS[field]
        col = meta["column"]
        ftype = meta["type"]

        # Alerted special boolean field
        if field in ("alerted", "is_alerted"):
            bool_val = self._validate_value(field, val)
            if (bool_val and op in (":", "==")) or (not bool_val and op == "!="):
                return "alert_count > 0"
            else:
                return "alert_count = 0"

        # Special Alert-level fields (joined with alerts table)
        if ftype == "alert_field":
            self.params.append(str(val))
            neg = "NOT " if op == "!=" else ""
            return f"{neg}flow_id IN (SELECT flow_id FROM alerts WHERE {col} = {self.param_placeholder} AND flow_id IS NOT NULL)"

        # Special Event-level fields (joined with packet_events table)
        if ftype == "event_field":
            p_val = f"%{val}%" if op in (":", "contains") else str(val)
            self.params.append(p_val)
            sql_op = "LIKE" if op in (":", "contains") else "="
            return f"flow_id IN (SELECT flow_id FROM packet_events WHERE payload_preview {sql_op} {self.param_placeholder} AND flow_id IS NOT NULL)"

        # CIDR IP handling
        if ftype == "ip" and "/" in str(val):
            try:
                net = ipaddress.ip_network(str(val).strip(), strict=False)
                prefix_len = net.prefixlen
                # For standard byte boundaries, optimize via LIKE prefix
                if net.version == 4 and prefix_len % 8 == 0:
                    octets = str(net.network_address).split(".")
                    oct_count = prefix_len // 8
                    like_prefix = ".".join(octets[:oct_count]) + ".%"
                    self.params.append(like_prefix)
                    return f"{col} LIKE {self.param_placeholder}"
                else:
                    # For other subnet masks, match prefix of string representation
                    ip_str = str(net.network_address)
                    base_prefix = ip_str.rsplit(".", 1)[0] + ".%"
                    self.params.append(base_prefix)
                    return f"{col} LIKE {self.param_placeholder}"
            except Exception:
                pass

        # Operator translation
        validated_val = self._validate_value(field, val)

        if op in (":", "=="):
            if isinstance(validated_val, str) and ftype == "string" and op == ":":
                self.params.append(f"%{validated_val}%")
                return f"{col} LIKE {self.param_placeholder}"
            else:
                self.params.append(validated_val)
                return f"{col} = {self.param_placeholder}"

        elif op == "!=":
            self.params.append(validated_val)
            return f"({col} != {self.param_placeholder} OR {col} IS NULL)"

        elif op == ">":
            self.params.append(validated_val)
            return f"{col} > {self.param_placeholder}"

        elif op == ">=":
            self.params.append(validated_val)
            return f"{col} >= {self.param_placeholder}"

        elif op == "<":
            self.params.append(validated_val)
            return f"{col} < {self.param_placeholder}"

        elif op == "<=":
            self.params.append(validated_val)
            return f"{col} <= {self.param_placeholder}"

        elif op == "contains":
            self.params.append(f"%{validated_val}%")
            return f"{col} LIKE {self.param_placeholder}"

        elif op == "startswith":
            self.params.append(f"{validated_val}%")
            return f"{col} LIKE {self.param_placeholder}"

        raise KqlParseError(f"Unsupported operator '{op}' for field '{field}'")


# ---------------------------------------------------------------------------
# Public API & Assistant
# ---------------------------------------------------------------------------

def parse_kql_to_sql(query_str: str, backend: str = "sqlite", dialect: Optional[str] = None) -> Tuple[str, List[Any]]:
    """
    Parse KQL query string and compile into parameterized SQL.
    Returns (sql_where_clause, parameter_list).
    """
    if not query_str or not query_str.strip():
        return "1=1", []

    target_backend = dialect or backend
    lexer = KqlLexer(query_str.strip())
    parser = KqlParser(lexer.tokens)
    ast = parser.parse()

    compiler = KqlCompiler(backend=target_backend)
    return compiler.compile(ast)


def generate_kql_from_intent(text: str) -> str:
    """
    Deterministic Query Generation Assistant.
    Converts common analyst intent statements into valid KQL queries.
    """
    s = text.strip()
    if not s:
        return ""

    # 1. IP Search Intent: "Find all traffic involving IP 10.64.85.221" or "IP 10.0.0.1"
    ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b", s)
    if ip_match:
        ip = ip_match.group(0)
        s_lower = s.lower()
        if "source" in s_lower and "destination" not in s_lower:
            return f'src_ip : "{ip}"'
        elif "destination" in s_lower and "source" not in s_lower:
            return f'dst_ip : "{ip}"'
        else:
            return f'src_ip : "{ip}" or dst_ip : "{ip}"'

    # 2. Port + Protocol Intent: "Find all TCP connections to port 443"
    proto_match = re.search(r"\b(tcp|udp|icmp)\b", s, re.I)
    port_match = re.search(r"\bport\s+(\d+)\b", s, re.I) or re.search(r":(\d+)\b", s)
    if proto_match and port_match:
        proto = proto_match.group(1).upper()
        port = int(port_match.group(1))
        return f'protocol : "{proto}" and dst_port : {port}'

    # 3. Port only: "Traffic on port 80"
    if port_match and not proto_match:
        port = int(port_match.group(1))
        return f"dst_port : {port} or src_port : {port}"

    # 4. Protocol + Packet count: "UDP traffic with more than 100 packets" or "High packet volume UDP traffic"
    if proto_match and ("packet" in s.lower() or "packets" in s.lower() or "volume" in s.lower()):
        p_num = re.search(r"\b(\d+)\s+packets?\b", s, re.I)
        proto = proto_match.group(1).upper()
        if p_num:
            return f'protocol : "{proto}" and packet_count > {p_num.group(1)}'
        return f'protocol : "{proto}" and packet_count > 100'

    # 5. Suspicious / High severity: "Show suspicious high-severity traffic"
    if "severity" in s.lower() or "suspicious" in s.lower() or "critical" in s.lower() or "high" in s.lower():
        if "alert" in s.lower():
            return "alerted : true"
        return 'severity : "high" or severity : "critical"'

    # 6. Alerted flows: "Show all flows with alerts"
    if "alert" in s.lower():
        return "alerted : true"

    # 7. DNS query: "DNS queries containing badactor"
    if "dns" in s.lower():
        dns_term = re.search(r'(?:containing|for|to)\s+["\']?([a-zA-Z0-9\.\-_]+)["\']?', s, re.I)
        if dns_term:
            return f'dns_query contains "{dns_term.group(1)}"'

    # Default fallback: quote string
    return f'"{s}"'
