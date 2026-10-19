"""ToolCallEnvelope 构造：调用身份与能力全部由网关状态签发。

模型只能提议工具与参数；call_id、trace_id、能力集、任务版本均由网关生成，
不接受模型自行声称的任何权限（DESIGN.md 第 3 节）。
"""

from __future__ import annotations

from typing import Any

from guard.contracts import ToolCallEnvelope, new_trace_id
from guard.gateway.registry import get_tool


def build_envelope(
    *,
    session_id: str,
    agent_id: str,
    agent_capabilities: frozenset[str],
    mission_version: int,
    tool: str,
    arguments: dict[str, Any],
    parent_call_id: str | None = None,
    trace_id: str | None = None,
) -> ToolCallEnvelope:
    spec = get_tool(tool)
    if spec is None:
        raise ValueError(f"未注册的工具: {tool!r}")
    if spec.name not in agent_capabilities:
        raise ValueError(f"工具 {tool!r} 不在 Agent 能力集内")
    return ToolCallEnvelope(
        session_id=session_id,
        agent_id=agent_id,
        agent_capabilities=agent_capabilities,
        mission_version=mission_version,
        tool=tool,
        arguments=arguments,
        parent_call_id=parent_call_id,
        trace_id=trace_id or new_trace_id(),
    )
