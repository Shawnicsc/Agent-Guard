"""MCP 中间代理：只连接预配置的上游 Server。"""

from guard.mcp_proxy.stdio_proxy import MCPServerConfig, StdioMCPProxy

__all__ = ["MCPServerConfig", "StdioMCPProxy"]
