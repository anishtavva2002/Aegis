"""MCP (Model Context Protocol) proxy: enforce Aegis policy on an agent's tool calls."""

from aegis.mcp.proxy import McpGuard, run_stdio_proxy

__all__ = ["McpGuard", "run_stdio_proxy"]
