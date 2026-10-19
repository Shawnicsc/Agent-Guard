"""子 Agent 派发执行器：独立身份与能力子集，由网关签发。

子 Agent 的可用能力必须是其父任务能力的子集；spawn 请求中携带的
capabilities 参数只作为申请，实际能力集由网关裁剪签发，
不接受模型文本声明（DESIGN.md 第 8 节）。子 Agent 的完整沙箱与
驱动在 C/D 阶段接入，B 阶段先落身份与能力记录。
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from guard.contracts import AuditEvent, EventType, ToolResult, new_id

if TYPE_CHECKING:  # 仅类型引用，避免与 session 循环导入
    from guard.gateway.session import GatewaySession


class SubagentExecutor:
    def __init__(self, session: GatewaySession) -> None:
        self.session = session

    def spawn(self, task: str, requested_capabilities: list[str],
              parent_call_id: str) -> ToolResult:
        parent_caps = set(self.session.agent_capabilities)
        # 网关签发：申请 ∩ 父能力；拒绝越权申请交给策略层（deny_capability_escalation）
        granted = sorted(parent_caps & set(requested_capabilities or []))
        agent_id = new_id("subagent")
        self.session.spawned_agents[agent_id] = (frozenset(granted), parent_call_id)
        self.session.store.append_event(AuditEvent(
            trace_id=self.session.trace_id,
            type=EventType.SUBAGENT_SPAWNED,
            session_id=self.session.mission.session_id,
            call_id=parent_call_id,
            agent_id=agent_id,
            payload={"task": task, "granted_capabilities": granted,
                     "requested": requested_capabilities},
        ))
        return ToolResult(ok=True, output=json.dumps({
            "agent_id": agent_id, "granted_capabilities": granted,
        }, ensure_ascii=False))
