"""标签传播引擎（C 阶段）：在 exact_bytes 之上扩展确定性改写与疑似关联。

传播基线（DESIGN.md 第 5 节）：
  exact_bytes —— 载荷中逐字节再现已登记片段（确定）
  field_copy / concat —— 参数携带片段的子串/拼接变体（确定性改写）
  inferred —— 模型改写/摘要后的疑似关联（非确定，只升级证据不直接定罪）

疑似关联结果以 suspected=True 标注，供 CONFIRM 档规则与审计使用，
绝不与 exact_bytes 同等触发 BLOCK 档（防误拦）。
"""

from __future__ import annotations

import base64
import difflib
import re
from dataclasses import dataclass

from guard.contracts import DataLabelName, PropagationBasis
from guard.taint.labels import LabelTracker, string_values

# 片段长度下限：低于此长度的片段不做相似度关联（噪声太大）
_MIN_ASSOCIATION_LEN = 16
# 相似度阈值：连续比值超过此值视为疑似关联
_ASSOCIATION_RATIO = 0.72
# 单值参数文本长度上限：超长内容不做相似度（性能保护）
_MAX_ASSOCIATE_VALUE_LEN = 4000


@dataclass
class PropagationHit:
    label: DataLabelName
    basis: PropagationBasis
    snippet: str
    evidence: str  # 载荷中疑似承载的值
    suspected: bool

    def to_payload(self) -> dict:
        return {"label": self.label.value, "basis": self.basis.value,
                "snippet": self.snippet[:80], "evidence": self.evidence[:80],
                "suspected": self.suspected}


class PropagationEngine:
    """会话级传播：包装 LabelTracker，统一三种基线的检查入口。"""

    def __init__(self, tracker: LabelTracker | None = None) -> None:
        self.tracker = tracker or LabelTracker()

    # ---- 登记（读取侧） ----

    def scan_and_register(self, text: str):
        return self.tracker.scan_and_register(text)

    # ---- 检查（调用侧） ----

    def exact_labels(self, arguments: dict) -> frozenset[DataLabelName]:
        """逐字节或可逆编码命中；编码后的外发仍按确定性传播处理。"""
        labels = set(self.tracker.labels_in(arguments))
        values = string_values(arguments)
        for snippet, snippet_labels in self.tracker.snippets:
            raw = snippet.encode("utf-8")
            variants = {
                base64.b64encode(raw).decode("ascii"),
                base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
            }
            if any(encoded in value for encoded in variants for value in values):
                labels.update(snippet_labels)
        return frozenset(labels)

    def substring_hits(self, arguments: dict) -> list[tuple[DataLabelName, str, str]]:
        """确定性改写：载荷值包含片段的子串（field_copy/concat）。

        例如片段 "api_key = sk-xxx" 的子串 "sk-xxx" 出现在参数里
        已由 exact_bytes 覆盖；此处覆盖片段本身被部分复制的情形，
        如 "aws_access_key_id=AKIA..." 去掉空格后的变体。
        """
        hits: list[tuple[DataLabelName, str, str]] = []
        values = string_values(arguments)
        for snippet, labels in self.tracker.snippets:
            compact = re.sub(r"[\s'\"]+", "", snippet)
            if len(compact) < _MIN_ASSOCIATION_LEN:
                continue
            for value in values:
                if compact in re.sub(r"[\s'\"]+", "", value):
                    for label in labels:
                        hits.append((label, snippet, value[:80]))
        return hits

    def infer_hits(self, arguments: dict) -> list[PropagationHit]:
        """疑似关联：模型改写后的近似承载（inferred，仅升级证据）。"""
        hits: list[PropagationHit] = []
        values = string_values(arguments)
        for snippet, labels in self.tracker.snippets:
            if len(snippet) < _MIN_ASSOCIATION_LEN:
                continue
            for value in values:
                if len(value) > _MAX_ASSOCIATE_VALUE_LEN:
                    continue
                if snippet in value:
                    continue  # 精确命中走 exact_bytes，不重复计
                if difflib.SequenceMatcher(None, snippet, value).ratio() >= _ASSOCIATION_RATIO:
                    for label in labels:
                        hits.append(PropagationHit(
                            label=label, basis=PropagationBasis.INFERRED,
                            snippet=snippet, evidence=value[:80], suspected=True,
                        ))
        return hits

    def carried_summary(self, arguments: dict) -> dict:
        """给审计与 CONFIRM 档规则用的完整传播摘要。"""
        exact = sorted({label.value for label in self.exact_labels(arguments)})
        substring = [{"label": label.value, "basis": PropagationBasis.CONCAT.value,
                      "snippet": snippet[:80]}
                     for label, snippet, _ in self.substring_hits(arguments)]
        inferred = [h.to_payload() for h in self.infer_hits(arguments)]
        return {"exact_labels": exact, "deterministic": substring,
                "suspected": inferred}
