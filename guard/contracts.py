"""核心数据契约（DESIGN.md 第 5 节）。

六个可信实体加事件模型，全部 Pydantic v2。所有模块只通过这些模型交换数据，
禁止各模块私建字段格式。
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, computed_field


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def new_trace_id() -> str:
    """W3C traceparent 兼容的 trace-id（32 hex）与 span-id（16 hex）。"""
    return secrets.token_hex(16)


def new_span_id() -> str:
    return secrets.token_hex(8)


def arguments_hash(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def content_hash(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


class TrustLevel(StrEnum):
    SYSTEM = "system"
    USER = "user"
    LOW = "low"


class SourceType(StrEnum):
    USER_MESSAGE = "user_message"
    WEB_PAGE = "web_page"
    FILE = "file"
    TOOL_RESULT = "tool_result"
    TOOL_DESCRIPTION = "tool_description"
    MCP_RESPONSE = "mcp_response"
    MEMORY = "memory"


class GoalCategory(StrEnum):
    CODE_REVIEW = "code_review"
    READ_DOCUMENT = "read_document"
    DATA_ANALYSIS = "data_analysis"
    GENERAL = "general"


class DataLabelName(StrEnum):
    SECRET = "secret"
    CREDENTIAL = "credential"
    PERSONAL_DATA = "personal_data"
    UNTRUSTED_INSTRUCTION = "untrusted_instruction"


class PropagationBasis(StrEnum):
    """标签传播依据：前三种为确定性，INFERRED 为疑似关联（DESIGN.md 第 9 节）。"""

    EXACT_BYTES = "exact_bytes"
    FIELD_COPY = "field_copy"
    CONCAT = "concat"
    INFERRED = "inferred"


class Span(BaseModel):
    """原文定位：原始字节区间与规范化文本区间，均 [start, end) 半开。"""

    raw_start: int
    raw_end: int
    normalized_start: int | None = None
    normalized_end: int | None = None


class MissionSpec(BaseModel):
    """可信任务意图快照。仅能由已认证用户经独立确认入口产生新版本；
    工具输出、网页与记忆不可修改（DESIGN.md 第 3 节）。"""

    session_id: str
    version: int = 1
    user_id: str
    goal: str
    goal_category: GoalCategory = GoalCategory.GENERAL
    allowed_resources: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    allow_exfiltration: bool = False
    allow_push: bool = False
    created_from_message_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class ContentSource(BaseModel):
    """网页、文件、工具返回、工具描述及记忆的统一来源记录。"""

    source_id: str = Field(default_factory=lambda: new_id("src"))
    type: SourceType
    uri: str
    trust_level: TrustLevel = TrustLevel.LOW
    content_hash: str
    parent_source_id: str | None = None
    span: Span | None = None


class ToolCallEnvelope(BaseModel):
    """执行前的唯一调用记录。真实参数与身份由网关状态签发，
    不接受模型自行声称的权限。"""

    call_id: str = Field(default_factory=lambda: new_id("call"))
    trace_id: str = Field(default_factory=new_trace_id)
    parent_call_id: str | None = None
    agent_id: str
    agent_capabilities: frozenset[str] = Field(default_factory=frozenset)
    session_id: str
    mission_version: int = 1
    tool: str
    arguments: dict[str, Any]
    ts: datetime = Field(default_factory=utcnow)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def arguments_hash(self) -> str:
        return arguments_hash(self.arguments)


class TaskRelation(StrEnum):
    ALIGNED = "aligned"
    DEVIATED = "deviated"
    UNCERTAIN = "uncertain"


class AttemptKind(StrEnum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    MEMORY = "memory"
    NONE = "none"


class SemanticFacts(BaseModel):
    """经 Schema 校验的模型分析结果。有限取值，禁止自然语言结论驱动执行器。"""

    task_relation: TaskRelation = TaskRelation.UNCERTAIN
    instruction_attempt: bool = False
    attempt_kind: AttemptKind = AttemptKind.NONE
    suspected_exfiltration: bool = False
    inferred_goal: str = ""
    evidence_source_ids: list[str] = Field(default_factory=list)
    evidence_quotes: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @classmethod
    def uncertain(cls) -> SemanticFacts:
        return cls(task_relation=TaskRelation.UNCERTAIN)


class RehearsalStatus(StrEnum):
    ATTRIBUTED = "attributed"
    NOT_ATTRIBUTED = "not_attributed"
    UNAVAILABLE = "unavailable"


class RehearsalFacts(BaseModel):
    """隔离副本的行为对照结果；只有 attributable 才能触发新禁令。"""

    status: RehearsalStatus
    signals: list[str] = Field(default_factory=list)
    replay_signals: list[str] = Field(default_factory=list)
    duration_ms: float = Field(default=0.0, ge=0.0)
    reason: str = ""
    source_count: int = 0
    replay_call_count: int = Field(default=0, ge=0)
    replay_tools: list[str] = Field(default_factory=list)
    cached: bool = False


class DecisionAction(StrEnum):
    ALLOW = "ALLOW"
    CONFIRM = "CONFIRM"
    BLOCK = "BLOCK"


class Decision(BaseModel):
    decision_id: str = Field(default_factory=lambda: new_id("dec"))
    call_id: str
    action: DecisionAction
    rule_ids: list[str] = Field(default_factory=list)
    matched_fields: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    policy_version: str = "stage-a-stub"
    arguments_hash: str
    approval_id: str | None = None
    degraded: bool = False
    ts: datetime = Field(default_factory=utcnow)


class DataLabel(BaseModel):
    source_id: str
    field_path: str
    labels: set[DataLabelName] = Field(default_factory=set)
    propagation_basis: PropagationBasis = PropagationBasis.INFERRED


class EventType(StrEnum):
    SESSION_CREATED = "session_created"
    MISSION_FROZEN = "mission_frozen"
    SANDBOX_STARTED = "sandbox_started"
    AGENT_STARTED = "agent_started"
    AGENT_DONE = "agent_done"
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"
    CALL_RECEIVED = "call_received"
    DECISION_MADE = "decision_made"
    SEMANTIC_ANALYZED = "semantic_analyzed"
    TOOL_EXECUTED = "tool_executed"
    TOOL_REFUSED = "tool_refused"
    SOURCE_RECORDED = "source_recorded"
    LABEL_ATTACHED = "label_attached"
    MEMORY_READ = "memory_read"
    MEMORY_WRITTEN = "memory_written"
    MCP_RELAYED = "mcp_relayed"
    SUBAGENT_SPAWNED = "subagent_spawned"
    # 沙箱绊网：沙箱内命令命中高危行为模式（rehearsal 阶段 2）
    TRIPWIRE_HIT = "tripwire_hit"
    REHEARSAL_STEP = "rehearsal_step"
    REHEARSAL_RUN = "rehearsal_run"
    ALERT = "alert"


class AuditEvent(BaseModel):
    """全链路审计事件。payload 为原文，redacted_payload 为脱敏后正文（B 阶段接入）。"""

    event_id: int | None = None
    ts: datetime = Field(default_factory=utcnow)
    trace_id: str
    type: EventType
    session_id: str | None = None
    call_id: str | None = None
    parent_call_id: str | None = None
    agent_id: str | None = None
    source_id: str | None = None
    decision_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    redacted_payload: dict[str, Any] | None = None


class ToolResult(BaseModel):
    """执行器返回给 Agent 的统一结果。失败时 ok=False 且 error 给出原因。"""

    ok: bool
    output: str = ""
    error: str = ""
    content_source_id: str | None = None
