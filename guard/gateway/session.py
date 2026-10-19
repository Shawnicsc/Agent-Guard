"""GatewaySession：一个任务会话的网关状态与决策/执行编排。

职责（DESIGN.md 第 3 节执行顺序）：
  接收调用请求 -> 签发 Envelope -> 规范化 -> 策略三态裁决 -> 受控执行 -> 审计落库。

裁决优先级（第 3 节）：硬性禁令 > 已批准的精确调用 > 需要确认 > 普通放行。
规则引擎或语义服务不可用时降级：写/命令/外发/推送/派发一律拒绝，
低风险只读操作放行并记 degraded 原因。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from guard.audit.store import AuditStore
from guard.config import settings
from guard.contracts import (
    AuditEvent,
    ContentSource,
    DataLabel,
    DataLabelName,
    Decision,
    DecisionAction,
    EventType,
    GoalCategory,
    MissionSpec,
    PropagationBasis,
    SemanticFacts,
    ToolCallEnvelope,
    ToolResult,
    new_id,
    new_trace_id,
)
from guard.gateway.envelope import build_envelope
from guard.gateway.executors.exec import ExecExecutor
from guard.gateway.executors.fs import FsExecutor
from guard.gateway.executors.git import GitExecutor
from guard.gateway.executors.net import NetExecutor
from guard.gateway.executors.subagent import SubagentExecutor
from guard.gateway.normalize import PathResolver
from guard.gateway.registry import all_tools, get_tool
from guard.policy.approval import create_approval, valid_approval
from guard.policy.dsl import compile_policy_file
from guard.policy.engine import PolicyEngine
from guard.policy.predicates import EvalContext
from guard.taint.labels import LabelTracker

log = logging.getLogger(__name__)

MAIN_AGENT_ID = "agent-main"
MAIN_CAPABILITIES = frozenset(all_tools().keys())

# 降级策略：高风险工具一律拒绝，低风险只读放行
_DEGRADED_ALLOW = frozenset({"fs.read"})
# CONFIRM 之外的读类工具默认视为可放行


class GatewaySession:
    def __init__(
        self,
        store: AuditStore,
        mission: MissionSpec,
        workspace_root: Path,
        container_name: str | None = None,
        trace_id: str | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.store = store
        self.mission = mission
        self.trace_id = trace_id
        self.workspace_root = workspace_root
        self.resolver = PathResolver({"workspace": workspace_root})
        self.container_name = container_name
        self.fs = FsExecutor(self.resolver)
        self.net = NetExecutor()
        self.git = GitExecutor(workspace_root)
        self.subagent = SubagentExecutor(self)
        self.exec = ExecExecutor(container_name) if container_name else None
        self.taint = LabelTracker()
        # 语义研判结果；C 阶段由 analyzer 写入，缺失时按 uncertain 保守处理
        self.semantic_facts: SemanticFacts | None = None
        if policy_engine is None:
            policy_engine = _load_default_engine()
        self.policy_engine = policy_engine

    # ---- 会话创建 ----

    @classmethod
    def create(
        cls,
        store: AuditStore,
        workspaces_root: Path,
        *,
        user_id: str,
        goal: str,
        goal_category: str = "general",
        allowed_resources: list[str] | None = None,
        allowed_actions: list[str] | None = None,
        allow_exfiltration: bool = False,
        allow_push: bool = False,
        policy_engine: PolicyEngine | None = None,
    ) -> GatewaySession:
        session_id = new_id("sess")
        trace_id = new_trace_id()
        mission = MissionSpec(
            session_id=session_id,
            user_id=user_id,
            goal=goal,
            goal_category=GoalCategory(goal_category),
            allowed_resources=allowed_resources or ["workspace://"],
            allowed_actions=allowed_actions or list(MAIN_CAPABILITIES),
            allow_exfiltration=allow_exfiltration,
            allow_push=allow_push,
        )
        workspace_root = workspaces_root / session_id
        workspace_root.mkdir(parents=True, exist_ok=True)
        store.save_session(session_id, user_id)
        store.save_mission(mission)
        store.append_event(AuditEvent(
            trace_id=trace_id, type=EventType.SESSION_CREATED,
            session_id=session_id, payload={"user_id": user_id},
        ))
        store.append_event(AuditEvent(
            trace_id=trace_id, type=EventType.MISSION_FROZEN,
            session_id=session_id, payload={"goal": goal, "version": mission.version},
        ))
        return cls(store, mission, workspace_root, trace_id=trace_id,
                  policy_engine=policy_engine)

    # ---- 调用链 ----

    def make_envelope(self, tool: str, arguments: dict[str, Any],
                      parent_call_id: str | None = None) -> ToolCallEnvelope:
        return build_envelope(
            session_id=self.mission.session_id,
            agent_id=MAIN_AGENT_ID,
            agent_capabilities=MAIN_CAPABILITIES,
            mission_version=self.mission.version,
            tool=tool,
            arguments=arguments,
            parent_call_id=parent_call_id,
            trace_id=self.trace_id,
        )

    def decide(self, envelope: ToolCallEnvelope) -> Decision:
        """三态裁决：硬规则 -> 已批准精确调用 -> CONFIRM -> 默认放行。"""
        self.store.save_call(envelope)
        self.store.append_event(AuditEvent(
            trace_id=envelope.trace_id, type=EventType.CALL_RECEIVED,
            session_id=envelope.session_id, call_id=envelope.call_id,
            agent_id=envelope.agent_id,
            payload={"tool": envelope.tool, "arguments": envelope.arguments},
        ))

        spec = get_tool(envelope.tool)
        if spec is None or spec.name not in envelope.agent_capabilities:
            decision = Decision(
                call_id=envelope.call_id, action=DecisionAction.BLOCK,
                reason=f"工具 {envelope.tool!r} 未注册或不在能力集内",
                arguments_hash=envelope.arguments_hash,
            )
        else:
            decision = self._decide_with_policy(envelope, spec)

        self.store.save_decision(decision)
        self.store.append_event(AuditEvent(
            trace_id=envelope.trace_id, type=EventType.DECISION_MADE,
            session_id=envelope.session_id, call_id=envelope.call_id,
            decision_id=decision.decision_id,
            payload={"action": decision.action.value, "rule_ids": decision.rule_ids,
                     "reason": decision.reason},
        ))
        return decision

    def _decide_with_policy(self, envelope: ToolCallEnvelope, spec) -> Decision:
        carried_labels = self.taint.labels_in(envelope.arguments)
        ctx = EvalContext(
            envelope=envelope, mission=self.mission,
            carried_labels=carried_labels,
            semantic_facts=self.semantic_facts,
            trusted_domains=frozenset(self.policy_engine.policy.trusted_domains),
        )
        try:
            result = self.policy_engine.decide(ctx)
        except Exception as exc:
            log.warning("策略引擎异常，走降级路径: %s", exc)
            return self._degraded_decision(envelope, spec)

        # 优先级：硬性禁令 > 已批准的精确调用 > 需要确认 > 默认放行
        if result.action == DecisionAction.BLOCK:
            return Decision(
                call_id=envelope.call_id, action=result.action,
                rule_ids=result.rule_ids, matched_fields=result.matched_fields,
                reason="；".join(result.reasons),
                policy_version=self.policy_engine.policy.version,
                arguments_hash=envelope.arguments_hash,
            )

        if result.action == DecisionAction.CONFIRM:
            # 已批准的精确调用：工具+参数一致且未过期 -> 放行（重试新 call_id 亦有效）
            approved = valid_approval(self.store, envelope.tool,
                                      envelope.arguments_hash, self.mission.user_id)
            if approved is not None:
                return Decision(
                    call_id=envelope.call_id, action=DecisionAction.ALLOW,
                    rule_ids=["approved_call", *result.rule_ids],
                    matched_fields=result.matched_fields,
                    reason=f"用户已批准（approval={approved.approval_id}，参数一致）",
                    policy_version=self.policy_engine.policy.version,
                    arguments_hash=envelope.arguments_hash,
                    approval_id=approved.approval_id,
                )
            approval = create_approval(
                self.store, envelope.call_id, envelope.arguments_hash,
                target=f"{envelope.tool} {envelope.arguments}",
                user_id=self.mission.user_id,
            )
            return Decision(
                call_id=envelope.call_id, action=result.action,
                rule_ids=result.rule_ids, matched_fields=result.matched_fields,
                reason="；".join(result.reasons),
                policy_version=self.policy_engine.policy.version,
                arguments_hash=envelope.arguments_hash,
                approval_id=approval.approval_id,
            )

        return Decision(
            call_id=envelope.call_id, action=result.action,
            rule_ids=result.rule_ids, matched_fields=result.matched_fields,
            reason="；".join(result.reasons) if result.reasons else "默认放行（未命中规则）",
            policy_version=self.policy_engine.policy.version,
            arguments_hash=envelope.arguments_hash,
        )

    def _degraded_decision(self, envelope: ToolCallEnvelope, spec) -> Decision:
        """引擎/语义不可用：高风险一律拒绝，低风险只读放行并记录原因。"""
        if spec.read_only and envelope.tool in _DEGRADED_ALLOW:
            action, reason = DecisionAction.ALLOW, "降级放行：低风险只读操作"
        else:
            action, reason = DecisionAction.BLOCK, "降级拒绝：策略引擎不可用，高风险操作拒绝"
        return Decision(
            call_id=envelope.call_id, action=action, reason=reason,
            policy_version="degraded", arguments_hash=envelope.arguments_hash,
            degraded=True,
        )

    def execute(self, envelope: ToolCallEnvelope) -> tuple[ToolResult, ContentSource | None]:
        """受控执行。只有 ALLOW 或有效批准才能到达这里。"""
        source: ContentSource | None = None
        result = ToolResult(ok=False, error="无可用执行器")
        if envelope.tool.startswith("fs."):
            if envelope.tool == "fs.read":
                result, source = self.fs.read(envelope.arguments.get("path", ""))
            elif envelope.tool == "fs.write":
                result = self.fs.write(
                    envelope.arguments.get("path", ""),
                    envelope.arguments.get("content", ""),
                )
        elif envelope.tool == "net.fetch":
            result, source = self.net.fetch(envelope.arguments.get("url", ""))
        elif envelope.tool == "exec.run":
            if self.exec is None:
                result = ToolResult(ok=False, error="任务沙箱未启动")
            else:
                result = self.exec.run(envelope.arguments.get("command", ""))
        elif envelope.tool == "git.push":
            result = self.git.push(envelope.arguments.get("remote", ""),
                                   envelope.arguments.get("branch", ""))
        elif envelope.tool == "agent.spawn":
            result = self.subagent.spawn(
                envelope.arguments.get("task", ""),
                envelope.arguments.get("capabilities") or [],
            )

        if source is not None:
            self.store.save_source(source)
            self._scan_result_content(envelope, source, result)
        event_type = EventType.TOOL_EXECUTED if result.ok else EventType.TOOL_REFUSED
        self.store.append_event(AuditEvent(
            trace_id=envelope.trace_id, type=event_type,
            session_id=envelope.session_id, call_id=envelope.call_id,
            agent_id=envelope.agent_id, source_id=source.source_id if source else None,
            payload={"tool": envelope.tool, "ok": result.ok,
                     "output": result.output[:2000], "error": result.error},
        ))
        return result, source

    def try_execute(self, envelope: ToolCallEnvelope,
                    decision: Decision) -> tuple[ToolResult, ContentSource | None]:
        """按裁决结果执行：ALLOW 直接执行；CONFIRM 需有效批准；BLOCK 拒绝。"""
        if decision.action == DecisionAction.ALLOW:
            return self.execute(envelope)
        if decision.action == DecisionAction.CONFIRM:
            approved = valid_approval(self.store, envelope.tool,
                                      envelope.arguments_hash, self.mission.user_id)
            if approved is not None:
                return self.execute(envelope)
            return (ToolResult(ok=False,
                               error=f"需用户确认（approval={decision.approval_id}），"
                                     "已创建待批准记录"), None)
        return (ToolResult(ok=False, error=f"网关拒绝: {decision.reason}"), None)

    def _scan_result_content(self, envelope: ToolCallEnvelope,
                             source: ContentSource, result: ToolResult) -> None:
        """工具结果进入 Agent 前标注来源敏感标签（B 阶段 exact_bytes 简版）。"""
        found = self.taint.scan_and_register(result.output)
        if not found:
            return
        labels: set[DataLabelName] = set()
        for _snippet, snippet_labels in found:
            labels |= set(snippet_labels)
        self.store.save_data_label(DataLabel(
            source_id=source.source_id, field_path="$.content", labels=labels,
            propagation_basis=PropagationBasis.EXACT_BYTES,
        ))
        self.store.append_event(AuditEvent(
            trace_id=envelope.trace_id, type=EventType.LABEL_ATTACHED,
            session_id=envelope.session_id, call_id=envelope.call_id,
            source_id=source.source_id,
            payload={"labels": [x.value for x in labels],
                     "snippets": len(found)},
        ))


def _load_default_engine() -> PolicyEngine:
    """加载默认策略；文件缺失或非法时抛错（策略是强制边界，不允许静默无策略）。"""
    return PolicyEngine(compile_policy_file(Path(settings.policy_file)))
