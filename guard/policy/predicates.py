"""谓词白名单注册表：每个谓词 = 名字 + 参数校验 + 求值函数。

配置里只允许出现这里注册的谓词；解释器绝不执行任意 Python（DESIGN.md 第 6 节）。
求值上下文 EvalContext 携带网关签发的事实，模型输出先校验为 SemanticFacts
再进入这里，不直接驱动执行器。
"""

from __future__ import annotations

import fnmatch
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from guard.contracts import (
    DataLabelName,
    MissionSpec,
    SemanticFacts,
    TaskRelation,
    ToolCallEnvelope,
)
from guard.gateway.normalize import decoded_variants, normalize_command_text

TRUSTED_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass
class EvalContext:
    envelope: ToolCallEnvelope
    mission: MissionSpec
    # 当前调用载荷携带的敏感标签（由 taint 传播计算，B 阶段为 exact_bytes 简版）
    carried_labels: frozenset[DataLabelName] = field(default_factory=frozenset)
    suspected_labels: frozenset[DataLabelName] = field(default_factory=frozenset)
    # 语义研判结果；None = 尚未分析，一律按 uncertain 保守处理
    semantic_facts: SemanticFacts | None = None
    # 信任域名集合，由策略文件 trusted_domains 提供并由引擎注入
    trusted_domains: frozenset[str] = field(default_factory=frozenset)


class PredicateDef:
    def __init__(self, validate: Callable[[Any], None],
                 evaluate: Callable[[Any, EvalContext], bool]):
        self._validate = validate
        self._evaluate = evaluate

    def validate_param(self, param: Any) -> None:
        self._validate(param)

    def evaluate(self, param: Any, ctx: EvalContext) -> bool:
        return self._evaluate(param, ctx)


def _check_str(name: str) -> Callable[[Any], None]:
    def validate(param: Any) -> None:
        if not isinstance(param, str) or not param:
            raise ValueError(f"{name} 参数必须是字符串")
    return validate


def _check_str_list(name: str) -> Callable[[Any], None]:
    def validate(param: Any) -> None:
        if isinstance(param, str):
            param = [param]
        if not isinstance(param, list) or not param or \
                not all(isinstance(p, str) for p in param):
            raise ValueError(f"{name} 参数必须是字符串或字符串列表")
    return validate


def _string_args(envelope: ToolCallEnvelope) -> list[str]:
    return [v for v in envelope.arguments.values() if isinstance(v, str)]


def _eval_action_is(param: str, ctx: EvalContext) -> bool:
    return ctx.envelope.tool == param


def _eval_path_under(param: list[str], ctx: EvalContext) -> bool:
    """任一路径类参数命中任一敏感前缀模式（fnmatch 通配）。"""
    patterns = [param] if isinstance(param, str) else param
    for value in _string_args(ctx.envelope):
        normalized = unicodedata.normalize("NFKC", value).strip()
        # 路径类参数：以 ~ 或 / 开头，或作为 fs.path 参数出现
        is_pathlike = normalized.startswith(("~", "/")) or "path" in ctx.envelope.arguments
        if not is_pathlike:
            continue
        for pattern in patterns:
            if fnmatch.fnmatchcase(normalized, pattern):
                return True
    return False


def _eval_destination_trust(param: str, ctx: EvalContext) -> bool:
    if param not in ("external", "trusted"):
        raise ValueError(f"destination_trust 参数必须是 external/trusted: {param!r}")
    url = ctx.envelope.arguments.get("url")
    if not isinstance(url, str):
        return False  # 无 URL 的调用不适用
    from guard.gateway.normalize import UrlError, normalize_url

    try:
        host, _ = normalize_url(url)
    except UrlError:
        return param == "external"  # 非法 URL 视为外部风险
    trusted = host in TRUSTED_LOCAL_HOSTS or host in ctx.trusted_domains
    return (not trusted) if param == "external" else trusted


def _eval_payload_has_label(param, ctx: EvalContext) -> bool:
    labels = {param} if isinstance(param, str) else set(param)
    return bool(ctx.carried_labels & labels)


def _eval_payload_suspected_label(param, ctx: EvalContext) -> bool:
    labels = {param} if isinstance(param, str) else set(param)
    return bool(ctx.suspected_labels & labels)


def _eval_mission_allows(param: str, ctx: EvalContext) -> bool:
    return param in ctx.mission.allowed_actions


def _eval_mission_goal_is(param: str, ctx: EvalContext) -> bool:
    # 赋值侧可能传入裸字符串（未开启 validate_assignment），统一取值
    category = ctx.mission.goal_category
    value = getattr(category, "value", category)
    return value == param


def _eval_mission_flag(param: str, ctx: EvalContext) -> bool:
    if param == "allow_exfiltration":
        return ctx.mission.allow_exfiltration
    if param == "allow_push":
        return ctx.mission.allow_push
    raise ValueError(f"未知任务标志: {param!r}")


def _eval_command_pattern(param: str, ctx: EvalContext) -> bool:
    command = ctx.envelope.arguments.get("command", "")
    if not isinstance(command, str) or not command:
        return False
    # 解码必须基于原始大小写（base64 是大小写敏感的），匹配再规范化
    variants = [normalize_command_text(command)] + decoded_variants(command)[1:]
    return any(re.search(param, variant) for variant in variants)


def _eval_capability_subset(param: bool, ctx: EvalContext) -> bool:
    if not isinstance(param, bool):
        raise ValueError("agent_capability_subset 参数必须是布尔值")
    requested = ctx.envelope.arguments.get("capabilities") or []
    if not isinstance(requested, list) or \
            not all(isinstance(c, str) for c in requested):
        return not param  # 缺省视为不满足"是子集"
    subset = set(requested) <= set(ctx.envelope.agent_capabilities)
    return subset == param


def _check_bool(name: str) -> Callable[[Any], None]:
    def validate(param: Any) -> None:
        if not isinstance(param, bool):
            raise ValueError(f"{name} 参数必须是布尔值")
    return validate


def _eval_semantic_task_relation(param: str, ctx: EvalContext) -> bool:
    if param not in {t.value for t in TaskRelation}:
        raise ValueError(f"semantic_task_relation 非法取值: {param!r}")
    facts = ctx.semantic_facts
    relation = facts.task_relation.value if facts is not None else TaskRelation.UNCERTAIN.value
    return relation == param


PREDICATES: dict[str, PredicateDef] = {
    "action_is": PredicateDef(_check_str("action_is"), _eval_action_is),
    "path_under": PredicateDef(_check_str_list("path_under"), _eval_path_under),
    "destination_trust": PredicateDef(_check_str("destination_trust"), _eval_destination_trust),
    "payload_has_label": PredicateDef(_check_str_list("payload_has_label"),
                                      _eval_payload_has_label),
    "payload_suspected_label": PredicateDef(
        _check_str_list("payload_suspected_label"), _eval_payload_suspected_label),
    "mission_allows": PredicateDef(_check_str("mission_allows"), _eval_mission_allows),
    "mission_goal_is": PredicateDef(_check_str("mission_goal_is"), _eval_mission_goal_is),
    "mission_flag": PredicateDef(_check_str("mission_flag"), _eval_mission_flag),
    "command_pattern": PredicateDef(_check_str("command_pattern"), _eval_command_pattern),
    "agent_capability_subset": PredicateDef(_check_bool("agent_capability_subset"),
                                             _eval_capability_subset),
    "semantic_task_relation": PredicateDef(_check_str("semantic_task_relation"),
                                           _eval_semantic_task_relation),
}
