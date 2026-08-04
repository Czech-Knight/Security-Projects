from __future__ import annotations

import re
from typing import Any


SENSITIVE_HEADER_NAMES = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key"}
SECRET_PATTERN = re.compile(
    r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|((?:password|token|secret|api[_-]?key|client_secret)\s*[=:]\s*)[^\s&,;]+"
)


def redact_headers(headers: dict[str, Any]) -> dict[str, str]:
    return {
        str(key): "[REDACTED]" if str(key).lower() in SENSITIVE_HEADER_NAMES else redact_text(str(value))
        for key, value in headers.items()
    }


def redact_text(text: str, secret_values: list[str] | None = None) -> str:
    result = SECRET_PATTERN.sub(lambda match: (match.group(1) or match.group(2) or "") + "[REDACTED]", text)
    for value in secret_values or []:
        if value and len(value) >= 4:
            result = result.replace(value, "[REDACTED]")
    return result
