"""语义研判器：LLM 结构化输出 -> SemanticFacts 校验 -> 审计落证。

分层触发（DESIGN.md 第 3 节）：硬规则不调模型；只对进入语义档
（semantic_task_relation 谓词）的调用做研判。研判失败的三条路径：
  1. 校验不合格重试耗尽 -> uncertain facts（保守分支，CONFIRM 档接管）
  2. LLM 服务不可用    -> None（会话标记 degraded，走降级裁决）
  3. 内容相同重复研判  -> content_hash 缓存直接命中
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from guard.contracts import (
    ContentSource,
    MissionSpec,
    SemanticFacts,
    ToolCallEnvelope,
    content_hash,
)
from guard.llm.client import LLMClient, LLMError
from guard.llm.schema import structured_call
from guard.semantic.prompts import build_analysis_messages
from guard.taint.detectors import injection_evidence

log = logging.getLogger(__name__)

# 送入模型的近期来源上限（注入定位需要原文证据，但也要控制提示体积）
MAX_ANALYSIS_SOURCES = 6
SOURCE_EXCERPT_CHARS = 600


@dataclass
class AnalysisRecord:
    facts: SemanticFacts | None
    cached: bool = False
    raw_response: str = ""
    sources_used: list[str] = field(default_factory=list)


class SemanticAnalyzer:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm
        # content_hash -> AnalysisRecord；会话内有效
        self._cache: dict[str, AnalysisRecord] = {}

    def analyze(self, mission: MissionSpec, envelope: ToolCallEnvelope,
                recent_sources: list[tuple[ContentSource, str]]) -> AnalysisRecord:
        """研判一次调用与冻结意图的关系。

        recent_sources: (来源记录, 原文片段) —— 片段由调用方从工具结果留存。
        """
        source_payload = [
            {"source_id": s.source_id, "type": s.type.value, "uri": s.uri,
             "excerpt": excerpt[:SOURCE_EXCERPT_CHARS]}
            for s, excerpt in recent_sources[-MAX_ANALYSIS_SOURCES:]
        ]
        key = content_hash(json.dumps({
            "mission_version": mission.version, "goal": mission.goal,
            "tool": envelope.tool,
            "arguments": envelope.arguments, "sources": source_payload,
        }, sort_keys=True, ensure_ascii=False))
        cached = self._cache.get(key)
        if cached is not None:
            return AnalysisRecord(facts=cached.facts, cached=True,
                                  raw_response=cached.raw_response,
                                  sources_used=cached.sources_used)

        messages = build_analysis_messages(mission, envelope, source_payload)
        try:
            facts, raw = structured_call(self.llm, messages, SemanticFacts)
        except LLMError as exc:
            log.warning("语义研判服务不可用: %s", exc)
            return AnalysisRecord(facts=None, raw_response=str(exc))
        if facts is None:
            # 重试耗尽：保守 uncertain，不信任未通过校验的输出
            facts = SemanticFacts.uncertain()
        # 确定性预检只证明来源中出现了可疑指令；不能单凭出现就断言
        # 本次调用偏离任务（例如 Agent 只是读取并报告该内容）。
        precheck = [
            injection_evidence(excerpt) for _s, excerpt in recent_sources
        ]
        if any(p["found"] for p in precheck) and not facts.instruction_attempt:
            quotes = [q for p in precheck for q in p["quotes"]][:5]
            facts = facts.model_copy(update={
                "instruction_attempt": True,
                "evidence_quotes": list(dict.fromkeys(
                    facts.evidence_quotes + quotes))[:5],
            })
        valid_sources = {s.source_id for s, _ in recent_sources}
        facts = facts.model_copy(update={
            "evidence_source_ids": [
                source_id for source_id in facts.evidence_source_ids
                if source_id in valid_sources
            ],
        })
        record = AnalysisRecord(facts=facts, raw_response=raw or "",
                                sources_used=[s.source_id for s, _ in recent_sources])
        self._cache[key] = record
        return record
