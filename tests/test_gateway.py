"""网关核心测试：决策桩、执行器路由、审计落库（无 Docker / 无 LLM 依赖）。"""

from __future__ import annotations

import respx
from httpx import Response

from guard.contracts import DecisionAction
from guard.gateway.registry import all_tools, openai_tools


def test_stub_decision_allow(session):
    envelope = session.make_envelope("fs.read", {"path": "README.md"})
    decision = session.decide(envelope)
    assert decision.action == DecisionAction.ALLOW
    assert decision.arguments_hash == envelope.arguments_hash
    # 调用与决策均落库
    rows = session.store._conn.execute("SELECT * FROM calls WHERE call_id = ?",
                                       (envelope.call_id,)).fetchall()
    assert len(rows) == 1
    events = session.store.events_by_trace(session.trace_id)
    types = [e["type"] for e in events]
    assert "call_received" in types
    assert "decision_made" in types
    assert "session_created" in types
    assert "mission_frozen" in types


def test_stub_decision_unknown_tool_block(session):
    envelope = session.make_envelope("fs.read", {"path": "x"})
    # 构造未注册工具：绕过 make_envelope 的注册检查直接构造 envelope
    from guard.contracts import ToolCallEnvelope

    bad = ToolCallEnvelope(
        session_id=envelope.session_id, agent_id=envelope.agent_id,
        agent_capabilities=envelope.agent_capabilities, tool="dangerous.tool",
        arguments={}, trace_id=envelope.trace_id,
    )
    decision = session.decide(bad)
    assert decision.action == DecisionAction.BLOCK
    assert "未注册" in decision.reason


def test_make_envelope_rejects_out_of_capability(session):
    import pytest

    from guard.gateway.envelope import build_envelope

    with pytest.raises(ValueError, match="能力集"):
        build_envelope(
            session_id=session.mission.session_id,
            agent_id="sub-1",
            agent_capabilities=frozenset({"fs.read"}),
            mission_version=1,
            tool="exec.run",
            arguments={"command": "ls"},
        )


def test_fs_write_then_read(session):
    w = session.make_envelope("fs.write", {"path": "notes/a.txt", "content": "hello"})
    assert session.decide(w).action == DecisionAction.ALLOW
    result, _ = session.execute(w)
    assert result.ok
    r = session.make_envelope("fs.read", {"path": "notes/a.txt"})
    result, source = session.execute(r)
    assert result.ok and result.output == "hello"
    assert source is not None and source.type.value == "file"


def test_fs_read_host_credential_refused(session):
    envelope = session.make_envelope("fs.read", {"path": "~/.ssh/id_rsa"})
    decision = session.decide(envelope)
    assert decision.action == DecisionAction.ALLOW  # 桩放行，由执行器硬边界拒绝
    result, _ = session.execute(envelope)
    assert not result.ok
    assert "路径被拒绝" in result.error
    # 拒绝也产生 tool_refused 事件
    events = session.store.events_by_trace(session.trace_id)
    assert any(e["type"] == "tool_refused" for e in events)


def test_fs_read_missing_file(session):
    envelope = session.make_envelope("fs.read", {"path": "nope.txt"})
    result, _ = session.execute(envelope)
    assert not result.ok and "不存在" in result.error


@respx.mock
def test_net_fetch_executed_and_sourced(session):
    respx.get("https://example.com/page").mock(
        return_value=Response(200, text="hello web"))
    envelope = session.make_envelope("net.fetch", {"url": "https://example.com/page"})
    result, source = session.execute(envelope)
    assert result.ok
    assert "hello web" in result.output
    assert source is not None and source.type.value == "web_page"
    assert source.uri == "https://example.com/page"


@respx.mock
def test_net_fetch_bad_scheme_refused(session):
    envelope = session.make_envelope("net.fetch", {"url": "file:///etc/passwd"})
    result, _ = session.execute(envelope)
    assert not result.ok and "URL 被拒绝" in result.error


def test_exec_without_sandbox(session):
    envelope = session.make_envelope("exec.run", {"command": "ls"})
    result, _ = session.execute(envelope)
    assert not result.ok and "沙箱未启动" in result.error


def test_session_trace_shared(session):
    """同会话所有 envelope 共享 trace_id（D 阶段 DAG 重建基础）。"""
    e1 = session.make_envelope("fs.read", {"path": "a"})
    e2 = session.make_envelope("fs.write", {"path": "b", "content": "x"})
    assert e1.trace_id == e2.trace_id == session.trace_id
    assert e1.call_id != e2.call_id


def test_registry_consistency():
    tools = all_tools()
    assert set(tools) == {"fs.read", "fs.write", "net.fetch", "exec.run"}
    openai_defs = openai_tools()
    assert {t["function"]["name"] for t in openai_defs} == set(tools)
    assert all(t["function"]["parameters"]["type"] == "object" for t in openai_defs)
