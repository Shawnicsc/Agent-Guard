"""三态裁决引擎：全部命中规则取最高严重度，携带完整证据。

裁决优先级固定（DESIGN.md 第 3 节）：硬性禁令 > 已批准的精确调用 > 需要确认 >
普通放行。BLOCK > CONFIRM > ALLOW；ALLOW 不覆盖更高优先级禁令。
引擎异常时由调用方走降级策略（写/命令/外发/推送/派发一律拒绝）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from guard.contracts import DecisionAction
from guard.policy.dsl import AndNode, CompiledRule, NotNode, OrNode, Predicate
from guard.policy.predicates import EvalContext

_SEVERITY = {DecisionAction.ALLOW: 1, DecisionAction.CONFIRM: 2, DecisionAction.BLOCK: 3}


@dataclass
class EngineResult:
    action: DecisionAction
    rule_ids: list[str] = field(default_factory=list)
    matched_fields: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    degraded: bool = False


def _collect_leaves(node) -> list[Predicate]:
    """收集条件树的全部叶子谓词，作为命中字段证据。"""
    if isinstance(node, Predicate):
        return [node]
    if isinstance(node, (AndNode, OrNode)):
        return [leaf for child in node.children for leaf in _collect_leaves(child)]
    if isinstance(node, NotNode):
        return _collect_leaves(node.child)
    return []


class PolicyEngine:
    def __init__(self, policy) -> None:
        self.policy = policy

    def uses_predicate(self, name: str) -> bool:
        return any(leaf.name == name for rule in self.policy.rules
                   for leaf in _collect_leaves(rule.condition))

    def decide(self, ctx: EvalContext) -> EngineResult:
        matched: list[CompiledRule] = []
        for rule in sorted(self.policy.rules, key=lambda r: -r.priority):
            try:
                if rule.matches(ctx):
                    matched.append(rule)
            except Exception as exc:
                # 调用方会转入降级裁决；不能把异常当成规则未命中。
                raise RuntimeError(f"规则 {rule.id} 求值失败") from exc
        if not matched:
            return EngineResult(action=self.policy.default_decision)
        # 最高严重度；同级别时保留全部命中
        action = max((r.decision for r in matched), key=lambda a: _SEVERITY[a])
        result = EngineResult(action=action)
        for rule in matched:
            if _SEVERITY[rule.decision] == _SEVERITY[action]:
                result.rule_ids.append(rule.id)
                result.reasons.append(rule.reason)
                result.matched_fields[rule.id] = [
                    {"predicate": leaf.name, "param": leaf.param}
                    for leaf in _collect_leaves(rule.condition)
                ]
        return result
