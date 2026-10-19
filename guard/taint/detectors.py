"""指令注入与敏感内容探测器：供语义分析、记忆守卫与来源扫描共用。

对抗语料覆盖（DESIGN.md 第 9 节）：中英文指令模板、零宽/全角混淆、
伪造系统消息、角色扮演诱导、代码注释/字符串伪装。命中只产生
untrusted_instruction 标签与证据片段，不直接驱动执行（裁决仍走策略）。
"""

from __future__ import annotations

import re
import unicodedata

from guard.contracts import DataLabelName

# 指令注入模式：返回 (片段, 证据句)。匹配前先做 NFKC + 剥离不可见字符。
_INJECTION_PATTERNS: list[tuple[DataLabelName, re.Pattern[str]]] = [
    (DataLabelName.UNTRUSTED_INSTRUCTION,
     re.compile(r"(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+|previous|prior|above|earlier)",
                re.IGNORECASE)),
    (DataLabelName.UNTRUSTED_INSTRUCTION,
     re.compile(r"忽略(?:之前|以上|前面|先前)?(?:的)?(?:所有)?(?:指令|要求|规则|指示)")),
    (DataLabelName.UNTRUSTED_INSTRUCTION,
     re.compile(r"(?:disregard|override)\s+(?:your|the|all)\s+(?:system|developer|safety|security)"
                r"\s+(?:prompt|instructions?|rules?)", re.IGNORECASE)),
    (DataLabelName.UNTRUSTED_INSTRUCTION,
     re.compile(r"\b(?:system|developer|assistant)\s*"
                r"(?:note|message|instruction)\s*[:：]", re.IGNORECASE)),
    (DataLabelName.UNTRUSTED_INSTRUCTION,
     re.compile(r"(?:you are now|从现在起(?:你是|你将))\s+(?:a|an|一个)?\s*(?:different|new|新的)?"
                r"(?:developer|admin|hacker|DAN)|开发者模式|developer mode", re.IGNORECASE)),
    (DataLabelName.UNTRUSTED_INSTRUCTION,
     re.compile(r"(?:send|post|upload|exfiltrate|上传|发送|外传)\s+(?:the\s+|this\s+|所有|全部|这些)?"
                r"(?:file|files|content|credentials?|secret|密钥|凭据|凭證|文件|内容)"
                r"\s*(?:to|至|到)\s*\S+|curl\s+[^|]*\||wget\s+[^|]*\|", re.IGNORECASE)),
    (DataLabelName.UNTRUSTED_INSTRUCTION,
     re.compile(r"(?:export|读取|查看|把|将).{0,24}"
                r"(?:\.ssh|\.aws|id_rsa|authorized_keys|/etc/passwd|/etc/shadow|"
                r"环境变量|\.env)", re.IGNORECASE)),
    (DataLabelName.UNTRUSTED_INSTRUCTION,
     re.compile(r"(?:execute|run|eval|exec|执行|运行|运行以下)"
                r"(?:\s+(?:this|the following|以下|如下))?\s*"
                r"(?:command|script|shell|代码|脚本|命令)"
                r"(?:\s*(?:now|immediately|立即|马上))?\s*[:：`]")),
]

# 零宽与不可见字符（WJ/ZWNJ/ZWSP/BOM/软连字符）—— 出现即视为混淆迹象
_INVISIBLE_RE = re.compile(r"[​‌‍⁠⁡﻿­]")


def normalize_for_detection(text: str) -> str:
    """检测前置规范化：NFKC、剥不可见字符、压缩空白。保留原始大小写。"""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def looks_confused(text: str) -> bool:
    """含原始不可见字符（规范化前）即判为混淆迹象。"""
    return bool(_INVISIBLE_RE.search(text))


def detect_injection(text: str) -> list[tuple[str, DataLabelName]]:
    """返回 (证据片段, 标签) 列表；空 = 未检出注入迹象。"""
    normalized = normalize_for_detection(text)
    hits: list[tuple[str, DataLabelName]] = []
    for label, pattern in _INJECTION_PATTERNS:
        for match in pattern.finditer(normalized):
            snippet = match.group(0).strip()
            if snippet and (snippet, label) not in hits:
                hits.append((snippet, label))
    return hits


def injection_evidence(text: str, max_quotes: int = 5) -> dict:
    """给语义分析/审计用的证据结构：命中句 + 是否混淆。"""
    hits = detect_injection(text)
    return {
        "found": bool(hits),
        "quotes": [q for q, _ in hits][:max_quotes],
        "labels": sorted({label.value for _, label in hits}),
        "obfuscation": looks_confused(text),
    }
