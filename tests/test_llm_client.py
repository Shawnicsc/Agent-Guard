"""LLM 客户端测试：本地与远程 provider 协议同构（respx 可重放 mock）。

铁律：同一客户端代码分别指向 mock 的本地端点与 Ark 端点，
请求与响应处理必须完全一致。
"""

from __future__ import annotations

import json
import os

import pytest
import respx
from httpx import Response

from guard.llm.client import LLMClient, LLMError
from guard.llm.config import ProviderConfig
from guard.llm.schema import structured_call

from .conftest import make_mock_llm

OPENAI_RESPONSE = {
    "choices": [
        {
            "message": {
                "content": "任务完成",
                "tool_calls": [
                    {
                        "id": "tc_1",
                        "type": "function",
                        "function": {"name": "fs.read", "arguments": "{\"path\": \"README.md\"}"},
                    }
                ],
            },
            "finish_reason": "tool_calls",
        }
    ],
    "usage": {"total_tokens": 42},
}


@respx.mock
def test_local_and_ark_same_protocol():
    """本地端点与 Ark 端点走同一客户端与同一响应解析。"""
    local = make_mock_llm("http://127.0.0.1:8080/v1")
    respx.post("http://127.0.0.1:8080/v1/chat/completions").mock(
        return_value=Response(200, json=OPENAI_RESPONSE))

    os.environ.pop("ARK_API_KEY", None)
    os.environ["ARK_API_KEY"] = "test-key"
    ark = LLMClient(
        ProviderConfig(base_url="https://ark.example/api/v3", model="doubao-test",
                       api_key_env="ARK_API_KEY", max_retries=0),
        "ark",
    )
    route = respx.post("https://ark.example/api/v3/chat/completions").mock(
        return_value=Response(200, json=OPENAI_RESPONSE))

    messages = [{"role": "user", "content": "你好"}]
    r_local = local.chat(messages)
    r_ark = ark.chat(messages)

    for r in (r_local, r_ark):
        assert r.content == "任务完成"
        assert len(r.tool_calls) == 1
        assert r.tool_calls[0].name == "fs.read"
        assert r.tool_calls[0].arguments == {"path": "README.md"}

    # Ark 请求必须带鉴权头，本地不必
    sent_ark = json.loads(route.calls.last.request.content)
    assert route.calls.last.request.headers["Authorization"] == "Bearer test-key"
    assert sent_ark["model"] == "doubao-test"
    # extra_body 合并：local 无，Ark 无
    assert "messages" in sent_ark


@respx.mock
def test_extra_body_merged_into_payload():
    client = LLMClient(
        ProviderConfig(base_url="http://127.0.0.1:8080/v1", model="qwen3",
                       extra_body={"chat_template_kwargs": {"enable_thinking": False}},
                       max_retries=0),
        "local",
    )
    route = respx.post("http://127.0.0.1:8080/v1/chat/completions").mock(
        return_value=Response(200, json=OPENAI_RESPONSE))
    client.chat([{"role": "user", "content": "hi"}])
    body = json.loads(route.calls.last.request.content)
    assert body["chat_template_kwargs"] == {"enable_thinking": False}


@respx.mock
def test_retry_then_success():
    client = LLMClient(ProviderConfig(base_url="http://x/v1", model="m", max_retries=2), "mock")
    route = respx.post("http://x/v1/chat/completions")
    route.side_effect = [
        Response(500, json={"error": "boom"}),
        Response(200, json=OPENAI_RESPONSE),
    ]
    r = client.chat([{"role": "user", "content": "hi"}])
    assert r.content == "任务完成"
    assert route.call_count == 2


@respx.mock
def test_retry_exhausted_raises():
    client = LLMClient(ProviderConfig(base_url="http://x/v1", model="m", max_retries=1), "mock")
    respx.post("http://x/v1/chat/completions").mock(
        return_value=Response(503, json={"error": "down"}))
    with pytest.raises(LLMError):
        client.chat([{"role": "user", "content": "hi"}])


@respx.mock
def test_tools_and_response_format_forwarded():
    client = make_mock_llm()
    route = respx.post("http://llm-mock.test/v1/chat/completions").mock(
        return_value=Response(200, json=OPENAI_RESPONSE))
    client.chat(
        [{"role": "user", "content": "hi"}],
        tools=[{"type": "function", "function": {"name": "fs.read", "parameters": {}}}],
        response_format={"type": "json_object"},
    )
    body = json.loads(route.calls.last.request.content)
    assert body["tools"][0]["function"]["name"] == "fs.read"
    assert body["response_format"] == {"type": "json_object"}


@respx.mock
def test_health_probes_models():
    client = make_mock_llm()
    respx.get("http://llm-mock.test/v1/health").mock(
        return_value=Response(200, json={"status": "ok"}))
    assert client.health() is True


@respx.mock
def test_health_falls_back_to_models():
    client = make_mock_llm()
    respx.get("http://llm-mock.test/v1/health").mock(
        return_value=Response(500, json={}))
    respx.get("http://llm-mock.test/v1/models").mock(
        return_value=Response(200, json={"data": []}))
    assert client.health() is True


@respx.mock
def test_structured_call_schema_retry():
    """JSON Schema 校验失败 -> 反馈重试 -> 成功。"""
    from pydantic import BaseModel

    class Facts(BaseModel):
        answer: int

    client = make_mock_llm()
    route = respx.post("http://llm-mock.test/v1/chat/completions")
    route.side_effect = [
        Response(200, json={"choices": [{"message": {"content": "不是 JSON"}}]}),
        Response(200, json={"choices": [{"message": {"content": '{"answer": 7}'}}]}),
    ]
    result, raw = structured_call(client, [{"role": "user", "content": "q"}], Facts)
    assert result is not None and result.answer == 7
    assert route.call_count == 2
    # 重试时把错误反馈带给了模型
    second_body = json.loads(route.calls[1].request.content)
    assert any("JSON" in m.get("content", "") for m in second_body["messages"])


@respx.mock
def test_structured_call_gives_up_to_uncertain():
    from pydantic import BaseModel

    from guard.contracts import SemanticFacts

    class Facts(BaseModel):
        answer: int

    client = make_mock_llm()
    respx.post("http://llm-mock.test/v1/chat/completions").mock(
        return_value=Response(200, json={"choices": [{"message": {"content": "垃圾"}}]}))
    result, raw = structured_call(client, [{"role": "user", "content": "q"}], Facts)
    assert result is None
    assert raw == "垃圾"
    # uncertain 兜底由调用方构造
    assert SemanticFacts.uncertain().task_relation.value == "uncertain"


@pytest.mark.parametrize("host", ["api.moonshot.cn", "api.deepseek.com"])
@respx.mock
def test_vendor_tool_names_round_trip_without_mutating_history(host):
    client = make_mock_llm(f"https://{host}/v1")
    response = json.loads(json.dumps(OPENAI_RESPONSE))
    response["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "fs_read"
    route = respx.post(f"https://{host}/v1/chat/completions").mock(
        return_value=Response(200, json=response))
    messages = [{"role": "assistant", "content": "", "tool_calls": [{
        "id": "previous", "type": "function",
        "function": {"name": "fs.read", "arguments": '{"path":"README.md"}'},
    }]}]
    tools = [{"type": "function", "function": {"name": "fs.read", "parameters": {}}}]
    result = client.chat(messages, tools=tools)
    sent = json.loads(route.calls.last.request.content)
    assert sent["tools"][0]["function"]["name"] == "fs_read"
    assert sent["messages"][0]["tool_calls"][0]["function"]["name"] == "fs_read"
    assert result.tool_calls[0].name == "fs.read"
    assert tools[0]["function"]["name"] == "fs.read"
    assert messages[0]["tool_calls"][0]["function"]["name"] == "fs.read"
