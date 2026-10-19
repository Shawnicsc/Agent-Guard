"""stdio MCP 代理：记录工具描述与返回文本的来源。

上游进程由部署配置提供，不能由 Agent 调用参数指定。对于不可信 Server，
部署方应将其命令指向单独的受限容器；代理本身不赋予上游宿主权限。
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from guard.contracts import ContentSource, SourceType, ToolResult, content_hash


@dataclass(frozen=True)
class MCPServerConfig:
    command: str
    args: tuple[str, ...]
    allowed_tools: frozenset[str]


class StdioMCPProxy:
    def __init__(self, servers: dict[str, MCPServerConfig]) -> None:
        self.servers = dict(servers)

    def list_tools(self, server: str) -> tuple[ToolResult, ContentSource | None]:
        config = self.servers.get(server)
        if config is None:
            return ToolResult(ok=False, error="MCP Server 未配置"), None
        try:
            tools = asyncio.run(self._list(config))
        except Exception as exc:
            return ToolResult(ok=False, error=f"MCP 列举失败: {exc}"), None
        descriptions = [
            {"name": tool.name, "description": tool.description or ""}
            for tool in tools if tool.name in config.allowed_tools
        ]
        text = json.dumps(descriptions, ensure_ascii=False)
        source = ContentSource(type=SourceType.TOOL_DESCRIPTION,
                               uri=f"mcp://{server}/tools",
                               content_hash=content_hash(text))
        return ToolResult(ok=True, output=text, content_source_id=source.source_id), source

    def call(self, server: str, name: str,
             arguments: dict) -> tuple[ToolResult, ContentSource | None]:
        config = self.servers.get(server)
        if config is None:
            return ToolResult(ok=False, error="MCP Server 未配置"), None
        if name not in config.allowed_tools:
            return ToolResult(ok=False, error="MCP 工具不在部署允许清单"), None
        try:
            reply = asyncio.run(self._call(config, name, arguments))
        except Exception as exc:
            return ToolResult(ok=False, error=f"MCP 调用失败: {exc}"), None
        text = "\n".join(
            block.text for block in reply.content if getattr(block, "type", None) == "text"
        )
        source = ContentSource(type=SourceType.MCP_RESPONSE,
                               uri=f"mcp://{server}/{name}",
                               content_hash=content_hash(text))
        return ToolResult(ok=not reply.is_error, output=text,
                          error="MCP 工具返回错误" if reply.is_error else "",
                          content_source_id=source.source_id), source

    @staticmethod
    async def _list(config: MCPServerConfig):
        params = StdioServerParameters(command=config.command, args=list(config.args))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                reply = await session.list_tools()
                return reply.tools

    @staticmethod
    async def _call(config: MCPServerConfig, name: str, arguments: dict):
        params = StdioServerParameters(command=config.command, args=list(config.args))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.call_tool(name, arguments)
