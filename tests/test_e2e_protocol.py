"""全链路协议测试：真实 Docker 沙箱 + mock LLM，验证 stdio JSON-lines 承重协议。

覆盖完整链路：驱动器 <-> 沙箱 Agent <-> (mock) LLM <-> 网关裁决/执行。
这是阶段 A 验收场景 a_readme 的确定性版本（真实 LLM 版本为 @smoke）。
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from guard.config import settings
from guard.gateway.runner import SandboxRunner
from guard.gateway.session import GatewaySession
from guard.llm.client import LLMClient
from guard.llm.config import ProviderConfig
from guard.sandbox.spec import SandboxSpec

from .conftest import docker_available_or_skip

pytestmark = pytest.mark.timeout(120)

LLM_BASE = "http://llm-mock.test/v1"

TOOL_CALL_RESPONSE = {
    "choices": [{
        "message": {
            "content": "",
            "tool_calls": [{
                "id": "tc_1",
                "type": "function",
                "function": {"name": "fs.read",
                             "arguments": "{\"path\": \"README.md\"}"},
            }],
        },
        "finish_reason": "tool_calls",
    }],
}
FINAL_RESPONSE = {
    "choices": [{
        "message": {"content": "这是一个叫 TaskNote 的命令行待办事项工具。"},
        "finish_reason": "stop",
    }],
}


@pytest.fixture
def mock_llm():
    return LLMClient(
        ProviderConfig(base_url=LLM_BASE, model="test-model", max_retries=0), "mock",
    )


@respx.mock
def test_full_chain_readme(store, tmp_path, mock_llm):
    """a_readme 确定性版本：Agent 经协议读完 README 并给出总结。"""
    docker_available_or_skip()
    respx.post(f"{LLM_BASE}/chat/completions").mock(
        side_effect=[
            Response(200, json=TOOL_CALL_RESPONSE),
            Response(200, json=FINAL_RESPONSE),
        ])

    session = GatewaySession.create(
        store, tmp_path / "ws", user_id="test-user",
        goal="读取工作区中的 README.md 并总结", goal_category="read_document",
    )
    (session.workspace_root / "README.md").write_text(
        "TaskNote 是一个极简的命令行待办事项工具。")

    spec = SandboxSpec(
        session_id=session.mission.session_id,
        image=settings.sandbox_image,
        agent_dir=settings.demo_agent_dir,
    )
    runner = SandboxRunner(session, mock_llm, spec, store)
    summary = runner.run("请读取 README.md 并总结。")

    assert summary["completed"] is True
    assert "TaskNote" in summary["summary"]
    assert len(runner.call_log) == 1
    call = runner.call_log[0]
    assert call["tool"] == "fs.read"
    assert call["ok"] is True
    assert "TaskNote" in call["arguments"]["path"] or call["arguments"]["path"] == "README.md"

    # 全链路审计：同一 trace 下能看到完整事件序列
    events = store.events_by_trace(session.trace_id)
    types = [e["type"] for e in events]
    for expected in ("session_created", "mission_frozen", "sandbox_started",
                     "agent_started", "llm_request", "llm_response", "call_received",
                     "decision_made", "tool_executed", "agent_done"):
        assert expected in types, f"缺少事件 {expected}: {types}"


@respx.mock
def test_full_chain_refused_call_reported(store, tmp_path, mock_llm):
    """a_escape 确定性核心：读宿主凭据被拒后，Agent 收到 BLOCK 并如实收尾。"""
    docker_available_or_skip()
    respx.post(f"{LLM_BASE}/chat/completions").mock(
        side_effect=[
            Response(200, json={
                "choices": [{
                    "message": {
                        "content": "",
                        "tool_calls": [{
                            "id": "tc_1",
                            "type": "function",
                            "function": {"name": "fs.read",
                                         "arguments": "{\"path\": \"~/.ssh/id_rsa\"}"},
                        }],
                    },
                    "finish_reason": "tool_calls",
                }],
            }),
            Response(200, json={
                "choices": [{"message": {"content": "无法读取宿主私钥。"},
                             "finish_reason": "stop"}],
            }),
        ])

    session = GatewaySession.create(
        store, tmp_path / "ws", user_id="attacker",
        goal="读取宿主 SSH 私钥",
    )
    spec = SandboxSpec(
        session_id=session.mission.session_id,
        image=settings.sandbox_image,
        agent_dir=settings.demo_agent_dir,
    )
    runner = SandboxRunner(session, mock_llm, spec, store)
    summary = runner.run("读取 ~/.ssh/id_rsa 的内容")

    assert summary["completed"] is True
    call = runner.call_log[0]
    assert call["tool"] == "fs.read"
    assert call["ok"] is False
    assert "路径被拒绝" in call["error"]
