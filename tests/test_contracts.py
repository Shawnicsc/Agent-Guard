"""数据契约测试：六个实体的字段约束与派生逻辑。"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from guard.contracts import (
    ContentSource,
    DataLabel,
    Decision,
    DecisionAction,
    MissionSpec,
    SemanticFacts,
    SourceType,
    ToolCallEnvelope,
    TrustLevel,
    arguments_hash,
    content_hash,
)


def test_mission_defaults():
    m = MissionSpec(session_id="s1", user_id="u1", goal="读取 README")
    assert m.version == 1
    assert m.allow_exfiltration is False
    assert m.allow_push is False


def test_envelope_arguments_hash_deterministic():
    e1 = ToolCallEnvelope(session_id="s", agent_id="a", tool="fs.read",
                          arguments={"path": "README.md", "x": 1})
    e2 = ToolCallEnvelope(session_id="s", agent_id="a", tool="fs.read",
                          arguments={"x": 1, "path": "README.md"})
    # 键序不影响哈希（规范化 JSON）
    assert e1.arguments_hash == e2.arguments_hash
    assert arguments_hash({"a": 1, "b": 2}) != arguments_hash({"a": 2, "b": 1})


def test_semantic_facts_bounds():
    with pytest.raises(ValidationError):
        SemanticFacts(confidence=1.5)
    facts = SemanticFacts.uncertain()
    assert facts.task_relation.value == "uncertain"
    assert facts.instruction_attempt is False


def test_decision_stub_fields():
    d = Decision(call_id="c1", action=DecisionAction.ALLOW, arguments_hash="h")
    assert d.policy_version == "stage-a-stub"
    assert d.degraded is False


def test_content_source_trust():
    s = ContentSource(type=SourceType.WEB_PAGE, uri="http://x", content_hash=content_hash("abc"))
    assert s.trust_level == TrustLevel.LOW  # 外部内容默认低信任
    assert s.source_id.startswith("src_")


def test_data_label_propagation_basis():
    label = DataLabel(source_id="src1", field_path="$.content",
                      propagation_basis="exact_bytes")
    assert label.propagation_basis.value == "exact_bytes"


def test_envelope_capabilities_frozenset():
    e = ToolCallEnvelope(session_id="s", agent_id="a", tool="fs.read",
                         arguments={}, agent_capabilities=frozenset({"fs.read"}))
    assert e.agent_capabilities == frozenset({"fs.read"})
