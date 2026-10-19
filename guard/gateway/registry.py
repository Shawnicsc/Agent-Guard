"""工具注册表：工具名、动作分类、OpenAI function 定义与执行器归属。

注册表是唯一权威：Agent 侧工具描述（examples/demo_agent/tools.py）与
网关侧执行器路由都必须与本表一致。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

ExecutorKey = Literal["fs", "net", "exec", "git", "subagent", "memory", "mcp"]


class ToolSpec(BaseModel):
    name: str
    executor: ExecutorKey
    read_only: bool
    description: str
    parameters: dict[str, Any]


_TOOLS: dict[str, ToolSpec] = {}


def _register(spec: ToolSpec) -> None:
    _TOOLS[spec.name] = spec


_register(ToolSpec(
    name="fs.read",
    executor="fs",
    read_only=True,
    description="读取工作区内指定路径的文本文件内容",
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string",
                        "description": "工作区内相对路径，如 README.md 或 docs/deploy.md"},
        },
        "required": ["path"],
    },
))

_register(ToolSpec(
    name="fs.write",
    executor="fs",
    read_only=False,
    description="将文本内容写入工作区内指定路径（覆盖写）",
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "工作区内相对路径"},
            "content": {"type": "string", "description": "要写入的文本内容"},
        },
        "required": ["path", "content"],
    },
))

_register(ToolSpec(
    name="net.fetch",
    executor="net",
    read_only=True,
    description="通过网关发起受控 HTTP GET 并返回响应正文"
                    "（沙箱自身无网络，所有联网必须经此工具）",
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标 URL，仅支持 http/https"},
        },
        "required": ["url"],
    },
))

_register(ToolSpec(
    name="exec.run",
    executor="exec",
    read_only=False,
    description="在任务沙箱容器内执行 shell 命令（不继承宿主凭据，无网络）",
    parameters={
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "要执行的 shell 命令"},
        },
        "required": ["command"],
    },
))


def get_tool(name: str) -> ToolSpec | None:
    return _TOOLS.get(name)


def all_tools() -> dict[str, ToolSpec]:
    return dict(_TOOLS)


def openai_tools(allowed: frozenset[str] | None = None) -> list[dict[str, Any]]:
    """OpenAI 协议 tools 数组（function calling），Agent 与 LLM 通用接口共用。"""
    return [
        {
            "type": "function",
            "function": {
                "name": spec.name,
                "description": spec.description,
                "parameters": spec.parameters,
            },
        }
        for spec in _TOOLS.values() if allowed is None or spec.name in allowed
    ]

_register(ToolSpec(
    name="git.push",
    executor="git",
    read_only=False,
    description="通过受控执行器把工作区仓库推送到远程（必须由任务授权）",
    parameters={
        "type": "object",
        "properties": {
            "remote": {"type": "string", "description": "远程名或 URL"},
            "branch": {"type": "string", "description": "要推送的分支"},
        },
        "required": ["remote", "branch"],
    },
))

_register(ToolSpec(
    name="agent.spawn",
    executor="subagent",
    read_only=False,
    description="派发一个子 Agent；可用能力只能是父任务能力的子集，"
                "由网关签发，不接受声明",
    parameters={
        "type": "object",
        "properties": {
            "task": {"type": "string", "description": "交给子 Agent 的任务描述"},
            "capabilities": {
                "type": "array", "items": {"type": "string"},
                "description": "申请的能力清单（必须是当前能力子集）",
            },
        },
        "required": ["task"],
    },
))

_register(ToolSpec(
    name="memory.write", executor="memory", read_only=False,
    description="将内容写入当前用户的跨会话记忆",
    parameters={"type": "object", "properties": {
        "key": {"type": "string"}, "content": {"type": "string"}},
        "required": ["key", "content"]},
))

_register(ToolSpec(
    name="memory.read", executor="memory", read_only=True,
    description="读取当前用户指定键的跨会话记忆",
    parameters={"type": "object", "properties": {"key": {"type": "string"}},
                "required": ["key"]},
))

_register(ToolSpec(
    name="mcp.list", executor="mcp", read_only=True,
    description="列举一个预配置 MCP Server 上已授权工具的描述",
    parameters={"type": "object", "properties": {"server": {"type": "string"}},
                "required": ["server"]},
))

_register(ToolSpec(
    name="mcp.call", executor="mcp", read_only=False,
    description="调用一个预配置 MCP Server 上已授权的工具",
    parameters={"type": "object", "properties": {
        "server": {"type": "string"}, "name": {"type": "string"},
        "arguments": {"type": "object"}},
        "required": ["server", "name", "arguments"]},
))
