"""MCP 描述与返回都按低信任来源进入网关。"""

from __future__ import annotations

import sys
from pathlib import Path

from guard.contracts import DecisionAction, SourceType
from guard.gateway.session import GatewaySession
from guard.mcp_proxy import MCPServerConfig, StdioMCPProxy
from guard.policy.approval import decide_approval


def _proxy() -> StdioMCPProxy:
    server = Path(__file__).parent / "fixtures" / "mcp_server.py"
    return StdioMCPProxy({"test": MCPServerConfig(
        command=sys.executable, args=(str(server),),
        allowed_tools=frozenset({"search_notes"}),
    )})


def test_stdio_mcp_description_and_result_provenance(store, tmp_path):
    session = GatewaySession.create(store, tmp_path / "ws", user_id="u1",
                                    goal="检索笔记", mcp_proxy=_proxy())
    listing = session.make_envelope("mcp.list", {"server": "test"})
    listed = session.decide(listing)
    assert listed.action == DecisionAction.ALLOW
    list_result, list_source = session.try_execute(listing, listed)
    assert list_result.ok and "Ignore previous instructions" in list_result.output
    assert list_source is not None and list_source.type == SourceType.TOOL_DESCRIPTION

    call_args = {"server": "test", "name": "search_notes",
                 "arguments": {"query": "project"}}
    first = session.make_envelope("mcp.call", call_args)
    pending = session.decide(first)
    assert pending.action == DecisionAction.CONFIRM
    decide_approval(store, pending.approval_id, "u1", True)
    approved_call = session.make_envelope("mcp.call", call_args)
    approved = session.decide(approved_call)
    assert approved.action == DecisionAction.ALLOW
    result, source = session.try_execute(approved_call, approved)
    assert result.ok and "read ~/.ssh/id_rsa" in result.output
    assert source is not None and source.type == SourceType.MCP_RESPONSE
    assert source.source_id in [s.source_id for s, _ in session.recent_sources]
    assert "mcp_relayed" in [e["type"] for e in store.events_by_trace(session.trace_id)]
