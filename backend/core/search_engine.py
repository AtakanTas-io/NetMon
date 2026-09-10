"""Faz 4 yapılandırılmış arama dili ve güvenli eşleştirme çekirdeği."""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass
from typing import Any


class SearchQueryError(ValueError):
    pass


FIELD_ALIASES = {
    "type": "device_type",
    "os": "os_text",
    "port": "open_ports",
    "loss": "packet_loss",
    "config": "config_text",
    "cert": "cert_status",
    "site": "site",
    "software": "software_text",
    "cve": "cves",
    "vlan": "vlan",
    "service": "service_text",
    "banner": "banner_text",
}
TEXT_FIELDS = {
    "ip",
    "mac",
    "hostname",
    "device_type",
    "vendor",
    "status",
    "site",
    "subnet",
    "switch_port",
    "vlan",
    "os_text",
    "software_text",
    "service_text",
    "banner_text",
    "config_text",
    "cert_status",
    "cves",
}
GENERIC_FIELDS = (
    "ip",
    "mac",
    "hostname",
    "device_type",
    "vendor",
    "status",
    "site",
    "subnet",
    "switch_port",
    "vlan",
    "os_text",
    "software_text",
    "service_text",
    "banner_text",
    "open_ports",
    "cert_status",
    "cves",
)


@dataclass(frozen=True)
class Term:
    field: str | None
    value: str
    regex: re.Pattern[str] | None = None


def tokenize(query: str) -> list[str]:
    if len(query) > 1000:
        raise SearchQueryError("Sorgu en fazla 1000 karakter olabilir.")
    tokens: list[str] = []
    buffer: list[str] = []
    quoted = False
    regex_mode = False
    escaped = False
    for char in query.strip():
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if char == "\\":
            buffer.append(char)
            escaped = True
            continue
        if char == '"' and not regex_mode:
            quoted = not quoted
            buffer.append(char)
            continue
        if char == "/" and not quoted and (regex_mode or (buffer and buffer[-1] == ":")):
            regex_mode = not regex_mode
            buffer.append(char)
            continue
        if char.isspace() and not quoted and not regex_mode:
            if buffer:
                tokens.append("".join(buffer))
                buffer = []
            continue
        if char in "()" and not quoted and not regex_mode:
            if buffer:
                tokens.append("".join(buffer))
                buffer = []
            tokens.append(char)
            continue
        buffer.append(char)
    if quoted or regex_mode:
        raise SearchQueryError("Kapanmamış tırnak veya regex ifadesi.")
    if buffer:
        tokens.append("".join(buffer))
    return tokens


def _safe_regex(raw: str) -> re.Pattern[str]:
    if len(raw) > 128:
        raise SearchQueryError("Regex en fazla 128 karakter olabilir.")
    if re.search(r"\\[1-9]|\(\?[=!<]|\(\?P|\(\?>|\(.*[+*].*\)[+*{]", raw):
        raise SearchQueryError("Regex; backreference, lookaround veya iç içe nicelik içeremez.")
    if re.search(r"(?<!\\)[+*]|\{\d+,\}", raw):
        raise SearchQueryError("Regex sınırsız nicelik içeremez; sabit veya üst sınırı belirli tekrar kullanın.")
    try:
        return re.compile(raw, re.IGNORECASE)
    except re.error as exc:
        raise SearchQueryError(f"Geçersiz regex: {exc}") from exc


def parse_term(token: str) -> Term:
    field = None
    value = token
    if ":" in token:
        candidate, value = token.split(":", 1)
        candidate = FIELD_ALIASES.get(candidate.casefold(), candidate.casefold())
        if candidate not in TEXT_FIELDS | {
            "open_ports",
            "latency",
            "packet_loss",
            "uptime",
            "last_seen",
            "verified",
            "config_changed",
        }:
            raise SearchQueryError(f"Desteklenmeyen alan: {candidate}")
        field = candidate
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    if not value:
        raise SearchQueryError("Boş arama değeri kullanılamaz.")
    regex = _safe_regex(value[1:-1]) if len(value) >= 2 and value.startswith("/") and value.endswith("/") else None
    return Term(field, value, regex)


def compile_query(query: str) -> list[Term | str]:
    raw = tokenize(query)
    if not raw:
        return []
    expanded: list[str] = []
    previous = None
    for token in raw:
        upper = token.upper()
        current = upper if upper in {"AND", "OR", "NOT"} else token
        if previous is not None:
            previous_is_value = previous not in {"AND", "OR", "NOT", "("}
            current_starts_value = current not in {"AND", "OR", ")"}
            if previous_is_value and current_starts_value:
                expanded.append("AND")
        expanded.append(current)
        previous = current

    output: list[Term | str] = []
    operators: list[str] = []
    precedence = {"OR": 1, "AND": 2, "NOT": 3}
    for token in expanded:
        if token == "(":
            operators.append(token)
        elif token == ")":
            while operators and operators[-1] != "(":
                output.append(operators.pop())
            if not operators:
                raise SearchQueryError("Dengesiz parantez.")
            operators.pop()
        elif token in precedence:
            while operators and operators[-1] != "(" and precedence[operators[-1]] >= precedence[token]:
                output.append(operators.pop())
            operators.append(token)
        else:
            output.append(parse_term(token))
    while operators:
        operator = operators.pop()
        if operator == "(":
            raise SearchQueryError("Dengesiz parantez.")
        output.append(operator)
    _validate_postfix(output)
    return output


def _validate_postfix(expression: list[Term | str]) -> None:
    depth = 0
    for item in expression:
        if isinstance(item, Term):
            depth += 1
        elif item == "NOT":
            if depth < 1:
                raise SearchQueryError("NOT operatörü için ifade eksik.")
        else:
            if depth < 2:
                raise SearchQueryError(f"{item} operatörü için ifade eksik.")
            depth -= 1
    if expression and depth != 1:
        raise SearchQueryError("Sorgu ifadesi tamamlanamadı.")


def _ip_matches(ip: str, value: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
        if "/" in value:
            return address in ipaddress.ip_network(value, strict=False)
        if "-" in value:
            left, right = value.split("-", 1)
            start = ipaddress.ip_address(left)
            end = ipaddress.ip_address(right if "." in right else ".".join(left.split(".")[:-1] + [right]))
            return int(start) <= int(address) <= int(end)
        return address == ipaddress.ip_address(value)
    except ValueError:
        return value.casefold() in ip.casefold()


def _numeric_matches(actual: Any, value: str, *, age: bool = False) -> bool:
    if actual is None:
        return False
    match = re.fullmatch(r"(<=|>=|<|>|=)?\s*([\d.]+)([smhd])?", value.casefold())
    if not match:
        raise SearchQueryError(f"Geçersiz sayısal karşılaştırma: {value}")
    operator, raw_number, unit = match.groups()
    expected = float(raw_number)
    if unit:
        expected *= {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    current = max(0.0, time.time() - float(actual)) if age else float(actual)
    return {
        "<": current < expected,
        "<=": current <= expected,
        ">": current > expected,
        ">=": current >= expected,
        "=": current == expected,
        None: current == expected,
    }[operator]


def term_matches(document: dict, term: Term) -> bool:
    fields = [term.field] if term.field else list(GENERIC_FIELDS)
    for field in fields:
        if field == "ip" and term.regex is None and _ip_matches(str(document.get("ip") or ""), term.value):
            return True
        if field in {"latency", "packet_loss", "uptime"} and _numeric_matches(document.get(field), term.value):
            return True
        if field == "last_seen" and _numeric_matches(document.get(field), term.value, age=True):
            return True
        if field in {"verified", "config_changed"}:
            expected = term.value.casefold() in {"1", "true", "yes", "evet"}
            if bool(document.get(field)) == expected:
                return True
            continue
        actual = document.get(field)
        if isinstance(actual, list):
            text = " ".join(str(item) for item in actual)
        else:
            text = str(actual or "")
        if term.regex and term.regex.search(text[:65536]):
            return True
        if not term.regex and term.value.casefold() in text.casefold():
            return True
    return False


def document_matches(document: dict, expression: list[Term | str]) -> bool:
    if not expression:
        return True
    stack: list[bool] = []
    for item in expression:
        if isinstance(item, Term):
            stack.append(term_matches(document, item))
        elif item == "NOT":
            stack.append(not stack.pop())
        else:
            right, left = stack.pop(), stack.pop()
            stack.append(left and right if item == "AND" else left or right)
    return stack[0]


def matched_fields(document: dict, expression: list[Term | str]) -> list[str]:
    return sorted(
        {term.field or "text" for term in expression if isinstance(term, Term) and term_matches(document, term)}
    )
