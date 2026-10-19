"""敏感内容标签（B 阶段最小实现：exact_bytes 传播）。

读取结果中检测到的密钥片段登记到会话；后续调用参数中再次出现这些
字节时判定为携带对应标签。摘要、改写等非确定性传播在 C 阶段扩展为
疑似关联标记。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guard.contracts import DataLabelName

# (标签, 正则, 捕获组)；片段长度下限防止误报噪声
_SECRET_PATTERNS: list[tuple[DataLabelName, re.Pattern[str]]] = [
    (DataLabelName.CREDENTIAL,
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    (DataLabelName.CREDENTIAL, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (DataLabelName.SECRET,
     re.compile(r"\b(?:api[_-]?(?:key|secret|token)|secret|token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/_\-]{16,})")),
    (DataLabelName.SECRET, re.compile(r"\b(?:password|passwd|pwd)\b['\"]?\s*[:=]\s*\S{8,}")),
    (DataLabelName.CREDENTIAL, re.compile(r"\bssh-rsa [A-Za-z0-9+/]{100,}")),
]

MIN_SNIPPET_LEN = 12


@dataclass
class LabelTracker:
    """会话级敏感片段登记簿（exact_bytes 传播）。"""

    snippets: list[tuple[str, frozenset[DataLabelName]]] = field(default_factory=list)

    def scan_and_register(self, text: str) -> list[tuple[str, frozenset[DataLabelName]]]:
        """扫描工具返回内容，登记命中的敏感片段，返回本次登记结果。

        除整个匹配串外，捕获组（如密钥值本身）也单独登记：
        载荷中只出现裸密钥值时同样能命中（exact_bytes）。
        """
        found: list[tuple[str, frozenset[DataLabelName]]] = []

        def _register(snippet: str | None, label: DataLabelName) -> None:
            if not snippet or len(snippet) < MIN_SNIPPET_LEN:
                return
            entry = (snippet.strip(), frozenset({label}))
            if entry not in self.snippets:
                self.snippets.append(entry)
            if entry not in found:
                found.append(entry)

        for label, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                _register(match.group(0), label)
                if pattern.groups >= 1:
                    _register(match.group(1), label)
        return found

    def labels_in(self, arguments: dict) -> frozenset[DataLabelName]:
        """检查调用参数是否包含已登记的敏感片段（字节一致匹配）。"""
        values = [v for v in arguments.values() if isinstance(v, str)]
        labels: set[DataLabelName] = set()
        for snippet, snippet_labels in self.snippets:
            if any(snippet in v for v in values):
                labels |= snippet_labels
        return frozenset(labels)
