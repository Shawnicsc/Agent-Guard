"""审计正文脱敏：密钥默认掩码，普通日志不落原文（DESIGN.md 第 9 节）。

需要原文复核时走单独权限的加密证据（D 阶段）；正文字段一律存脱敏副本。
"""

from __future__ import annotations

import re
from typing import Any

_REDACT_PATTERNS: list[tuple[str, str]] = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
     "[REDACTED:PRIVATE_KEY]"),
    (r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED:AWS_KEY]"),
    (r"\b(api_?key|secret|token|password|passwd)(['\"]?\s*[:=]\s*['\"]?)\S+",
     r"\1\2[REDACTED:SECRET]"),
]


def redact_text(text: str) -> str:
    for pattern, replacement in _REDACT_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


_SENSITIVE_KEY_RE = re.compile(r"(api_?key|secret|token|password|passwd)", re.IGNORECASE)


def redact_payload(payload: Any) -> Any:
    """递归脱敏：字符串值掩码，结构保持不变。

    键名本身命中敏感词（如 {"secret": "..."}）时，其字符串值直接掩码，
    不要求值文本里也出现赋值语法。
    """
    if isinstance(payload, str):
        return redact_text(payload)
    if isinstance(payload, dict):
        return {
            k: "[REDACTED:SECRET]"
            if isinstance(v, str) and _SENSITIVE_KEY_RE.search(str(k))
            else redact_payload(v)
            for k, v in payload.items()
        }
    if isinstance(payload, list):
        return [redact_payload(v) for v in payload]
    return payload
