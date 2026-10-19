"""裁决引擎与会话集成测试：优先级、命中证据、降级路径（无 LLM/外部依赖）。"""

from __future__ import annotations

from guard.config import settings
from guard.contracts import DecisionAction, SemanticFacts, TaskRelation
from guard.policy.dsl import compile_policy_file
from guard.policy.engine import PolicyEngine
from guard.policy.predicates import EvalContext


def _default_engine() -> PolicyEngine:
    return PolicyEngine(compile_policy_file(settings.policy_file))


def _ctx(session, tool, arguments, **overrides) -> EvalContext:
    envelope = session.make_envelope(tool, arguments)
    kw = dict(envelope=envelope, mission=session.mission,
              trusted_domains=frozenset(_default_engine().policy.trusted_domains))
    kw.update(overrides)
    return EvalContext(**kw)


# ---- 引擎：优先级与证据 ----


def test_block_beats_confirm_and_allow(session):
    """同一调用命中多条规则时取最高严重度，仅保留同级别的命中集合。"""
    engine = _default_engine()
    ctx = _ctx(session, "fs.write", {"path": "~/.ssh/authorized_keys", "content": "k"})
    result = engine.decide(ctx)
    assert result.action == DecisionAction.BLOCK
    assert "deny_sensitive_write" in result.rule_ids
    # 更低严重度的 confirm_unplanned_write 也命中，但不进入 rule_ids
    assert "confirm_unplanned_write" not in result.rule_ids
    assert result.matched_fields["deny_sensitive_write"]


def test_all_same_severity_rules_reported(session):
    """同严重度命中全部上报（git.push 在检视任务下双规则命中）。"""
    engine = _default_engine()
    session.mission.goal_category = "code_review"
    result = engine.decide(_ctx(session, "git.push", {"remote": "o", "branch": "m"}))
    assert result.action == DecisionAction.BLOCK
    assert set(result.rule_ids) == {"deny_review_push", "deny_unauthorized_push"}


def test_no_match_falls_to_default(session):
    engine = _default_engine()
    result = engine.decide(_ctx(session, "fs.read", {"path": "README.md"}))
    assert result.action == DecisionAction.ALLOW
    assert result.rule_ids == []


def test_broken_rule_skipped_not_fatal(session):
    """单条规则求值异常只跳过该规则，不影响其余规则的裁决。"""
    # 注入一条非法正则的高优先级 BLOCK 规则，验证它被跳过后不影响放行
    broken = compile_policy_file(settings.policy_file)
    from guard.contracts import DecisionAction as DA
    from guard.policy.dsl import CompiledRule, Predicate

    bad_rule = CompiledRule(
        id="bad_regex", priority=999, decision=DA.BLOCK, reason="broken",
        condition=Predicate(name="command_pattern", param="([unclosed"),
    )
    broken.rules = list(broken.rules) + [bad_rule]
    result = PolicyEngine(broken).decide(_ctx(session, "fs.read", {"path": "x"}))
    assert result.action == DecisionAction.ALLOW


# ---- 会话集成 ----


def test_session_decision_carries_policy_evidence(session):
    envelope = session.make_envelope("fs.write", {"path": "~/.ssh/x", "content": "k"})
    decision = session.decide(envelope)
    assert decision.action == DecisionAction.BLOCK
    assert decision.policy_version == session.policy_engine.policy.version
    assert "deny_sensitive_write" in decision.rule_ids
    assert decision.matched_fields
    # 落库
    row = session.store.get_decision(decision.decision_id)
    assert row is not None and row["action"] == "BLOCK"


def test_session_aligned_write_allowed(session):
    session.semantic_facts = SemanticFacts(task_relation=TaskRelation.ALIGNED)
    envelope = session.make_envelope("fs.write", {"path": "notes.txt", "content": "hi"})
    decision = session.decide(envelope)
    assert decision.action == DecisionAction.ALLOW


def test_session_degraded_on_engine_failure(store, tmp_path):
    """引擎异常 -> 降级：只读放行、高风险拒绝，全部标记 degraded。"""
    from guard.gateway.session import GatewaySession

    class ExplodingEngine:
        def __init__(self):
            self.policy = compile_policy_file(settings.policy_file)

        def decide(self, ctx):
            raise RuntimeError("模拟引擎故障")

    session = GatewaySession.create(
        store, tmp_path / "ws", user_id="u", goal="g",
        policy_engine=ExplodingEngine(),
    )
    read = session.decide(session.make_envelope("fs.read", {"path": "x"}))
    assert read.action == DecisionAction.ALLOW and read.degraded
    write = session.decide(session.make_envelope("fs.write", {"path": "x", "content": "y"}))
    assert write.action == DecisionAction.BLOCK and write.degraded
    assert write.policy_version == "degraded"
