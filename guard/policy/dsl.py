"""策略 DSL：YAML -> Pydantic 校验 -> 内部 AST。

只支持已注册谓词与字面量参数，禁止任意 Python 表达式（DESIGN.md 第 6 节）。
加载时做类型校验；编译失败的策略版本整体拒绝。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from guard.contracts import DecisionAction
from guard.policy.predicates import PREDICATES


class PolicyError(ValueError):
    pass


# ---- AST 节点 ----


class Predicate(BaseModel):
    name: str
    param: Any

    def evaluate(self, ctx) -> bool:
        return PREDICATES[self.name].evaluate(self.param, ctx)


class AndNode(BaseModel):
    children: list[Any]

    def evaluate(self, ctx) -> bool:
        return all(_eval_node(child, ctx) for child in self.children)


class OrNode(BaseModel):
    children: list[Any]

    def evaluate(self, ctx) -> bool:
        return any(_eval_node(child, ctx) for child in self.children)


class NotNode(BaseModel):
    child: Any

    def evaluate(self, ctx) -> bool:
        return not _eval_node(self.child, ctx)


def _eval_node(node: Any, ctx) -> bool:
    if isinstance(node, (Predicate, AndNode, OrNode, NotNode)):
        return node.evaluate(ctx)
    raise PolicyError(f"未知 AST 节点: {node!r}")


# ---- 规则模型 ----


class RuleModel(BaseModel):
    id: str
    priority: int = Field(ge=0, le=1000)
    when: dict[str, Any]
    decision: DecisionAction
    reason: str = ""

    @field_validator("when")
    @classmethod
    def _when_not_empty(cls, v):
        if not v:
            raise PolicyError("when 条件不能为空")
        return v


class PolicyFile(BaseModel):
    version: str
    trusted_domains: list[str] = Field(default_factory=list)
    default_decision: DecisionAction = DecisionAction.ALLOW
    rules: list[RuleModel]


def _compile_condition(spec: dict[str, Any]) -> Any:
    """把 when 子树编译为 AST。叶子是单键谓词映射；all/any/not 可任意嵌套。"""
    if not isinstance(spec, dict) or len(spec) == 0:
        raise PolicyError(f"非法条件节点: {spec!r}")
    if len(spec) != 1:
        raise PolicyError(f"条件节点必须是单键: {spec!r}")
    key, value = next(iter(spec.items()))
    if key == "all":
        return AndNode(children=[_compile_condition(c) for c in value])
    if key == "any":
        return OrNode(children=[_compile_condition(c) for c in value])
    if key == "not":
        return NotNode(child=_compile_condition(value))
    if key in PREDICATES:
        PREDICATES[key].validate_param(value)
        return Predicate(name=key, param=value)
    raise PolicyError(f"未注册的谓词: {key!r}，可用: {sorted(PREDICATES)}")


class CompiledRule(BaseModel):
    model_config = {"arbitrary_types_allowed": True}

    id: str
    priority: int
    decision: DecisionAction
    reason: str
    condition: Any  # AST 节点

    def matches(self, ctx) -> bool:
        return _eval_node(self.condition, ctx)


class CompiledPolicy:
    def __init__(self, file: PolicyFile, rules: list[CompiledRule]) -> None:
        self.file = file
        self.rules = rules
        self.version = file.version
        self.trusted_domains = set(file.trusted_domains)
        self.default_decision = file.default_decision


def compile_policy_text(text: str) -> CompiledPolicy:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise PolicyError("策略文件必须是 YAML 映射")
    file = PolicyFile.model_validate(data)
    compiled: list[CompiledRule] = []
    seen_ids: set[str] = set()
    for rule in file.rules:
        if rule.id in seen_ids:
            raise PolicyError(f"规则 ID 重复: {rule.id}")
        seen_ids.add(rule.id)
        compiled.append(CompiledRule(
            id=rule.id, priority=rule.priority, decision=rule.decision,
            reason=rule.reason, condition=_compile_condition(rule.when),
        ))
    return CompiledPolicy(file, compiled)


def compile_policy_file(path: Path) -> CompiledPolicy:
    return compile_policy_text(path.read_text())
