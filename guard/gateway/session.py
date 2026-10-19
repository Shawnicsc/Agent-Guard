"""GatewaySession：一个任务会话的网关状态与决策/执行编排。

职责（DESIGN.md 第 3 节执行顺序）：
  接收调用请求 -> 签发 Envelope -> 规范化 -> 决策（A 阶段为桩）-> 受控执行 -> 审计落库。

A 阶段决策桩：未注册/越权工具 BLOCK，其余一律 ALLOW（安全由沙箱硬边界保证）；
B 阶段由 policy.engine 替换桩，接口不变。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from guard.audit.store import AuditStore
from guard.contracts import (
    AuditEvent,
    ContentSource,
    Decision,
    DecisionAction,
    EventType,
    GoalCategory,
    MissionSpec,
    ToolCallEnvelope,
    ToolResult,
    new_id,
    new_trace_id,
)
from guard.gateway.envelope import build_envelope
from guard.gateway.executors.exec import ExecExecutor
from guard.gateway.executors.fs import FsExecutor
from guard.gateway.executors.net import NetExecutor
from guard.gateway.normalize import PathResolver
from guard.gateway.registry import all_tools

log = logging.getLogger(__name__)

MAIN_AGENT_ID = "agent-main"
MAIN_CAPABILITIES = frozenset(all_tools().keys())


class GatewaySession:
    def __init__(
        self,
        store: AuditStore,
        mission: MissionSpec,
        workspace_root: Path,
        container_name: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        self.store = store
        self.mission = mission
        self.trace_id = trace_id
        self.workspace_root = workspace_root
        self.resolver = PathResolver({"workspace": workspace_root})
        self.container_name = container_name
        self.fs = FsExecutor(self.resolver)
        self.net = NetExecutor()
        self.exec = ExecExecutor(container_name) if container_name else None

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
        return cls(store, mission, workspace_root, trace_id=trace_id)

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
        """A 阶段桩：未知/越权工具 BLOCK，其余 ALLOW。B 阶段替换为策略引擎。"""
        from guard.gateway.registry import get_tool

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
            decision = Decision(
                call_id=envelope.call_id, action=DecisionAction.ALLOW,
                reason="stage-a 桩决策：沙箱硬边界兜底",
                arguments_hash=envelope.arguments_hash,
            )
        self.store.save_decision(decision)
        self.store.append_event(AuditEvent(
            trace_id=envelope.trace_id, type=EventType.DECISION_MADE,
            session_id=envelope.session_id, call_id=envelope.call_id,
            decision_id=decision.decision_id,
            payload={"action": decision.action.value, "reason": decision.reason},
        ))
        return decision

    def execute(self, envelope: ToolCallEnvelope) -> tuple[ToolResult, ContentSource | None]:
        """受控执行。只有 ALLOW 才允许到达这里。"""
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

        if source is not None:
            self.store.save_source(source)
        event_type = EventType.TOOL_EXECUTED if result.ok else EventType.TOOL_REFUSED
        self.store.append_event(AuditEvent(
            trace_id=envelope.trace_id, type=event_type,
            session_id=envelope.session_id, call_id=envelope.call_id,
            agent_id=envelope.agent_id, source_id=source.source_id if source else None,
            payload={"tool": envelope.tool, "ok": result.ok,
                     "output": result.output[:2000], "error": result.error},
        ))
        return result, source
