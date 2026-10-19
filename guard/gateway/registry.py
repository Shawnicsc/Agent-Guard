"""工具注册表：工具名、动作分类、OpenAI function 定义与执行器归属。

注册表是唯一权威：Agent 侧工具描述（examples/demo_agent/tools.py）与
网关侧执行器路由都必须与本表一致。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

ExecutorKey = Literal["fs", "net", "exec"]


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


def openai_tools() -> list[dict[str, Any]]:
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
        for spec in _TOOLS.values()
    ]
