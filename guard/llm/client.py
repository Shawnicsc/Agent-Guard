"""OpenAI 协议统一客户端（httpx 直连，不引入 openai SDK）。

本地 llama.cpp server 与远程 Ark 同构调用；便于 respx 在 HTTP 层做可重放 mock。
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

from guard.llm.config import ProviderConfig

log = logging.getLogger(__name__)


class ToolCall(BaseModel):
    """OpenAI 协议 tool_calls 数组中的一项。"""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class LLMResponse(BaseModel):
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    finish_reason: str = ""
    usage: dict[str, Any] = Field(default_factory=dict)


class LLMError(RuntimeError):
    pass


class LLMClient:
    """chat(messages, tools, response_format) -> LLMResponse。

    provider 配置只影响 base_url / key / timeout / extra_body，
    请求与响应处理对本地与远程完全一致。
    """

    def __init__(self, provider: ProviderConfig, provider_name: str = "") -> None:
        if not provider.model:
            raise LLMError(f"provider {provider_name!r} 未配置 model")
        self.provider = provider
        self.provider_name = provider_name
        self._client = httpx.Client(
            base_url=provider.base_url,
            timeout=provider.timeout_s,
            headers=self._headers(),
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        key = self.provider.api_key()
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def _payload(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        response_format: dict[str, Any] | None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.provider.model, "messages": messages}
        if tools:
            body["tools"] = tools
        if response_format:
            body["response_format"] = response_format
        if self.provider.extra_body:
            body.update(self.provider.extra_body)
        return body

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> LLMResponse:
        body = self._payload(messages, tools, response_format)
        last_error: Exception | None = None
        for attempt in range(self.provider.max_retries + 1):
            try:
                resp = self._client.post("/chat/completions", json=body)
                resp.raise_for_status()
                return _parse_response(resp.json())
            except (httpx.HTTPError, LLMError, ValueError) as exc:
                last_error = exc
                log.warning(
                    "LLM 调用失败 (provider=%s attempt=%d/%d): %s",
                    self.provider_name,
                    attempt + 1,
                    self.provider.max_retries + 1,
                    exc,
                )
        raise LLMError(f"LLM 调用重试耗尽: {last_error}") from last_error

    def health(self) -> bool:
        """启动时探活：llama.cpp /health，OpenAI 兼容端点 /models。"""
        for path in ("/health", "/models"):
            try:
                resp = self._client.get(path)
                if resp.status_code < 500:
                    return True
            except httpx.HTTPError:
                continue
        return False


def _parse_response(data: dict[str, Any]) -> LLMResponse:
    choices = data.get("choices") or []
    if not choices:
        raise LLMError(f"响应缺少 choices: {data}")
    choice = choices[0]
    message = choice.get("message") or {}
    tool_calls = []
    for tc in message.get("tool_calls") or []:
        fn = tc.get("function") or {}
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except ValueError:
            args = {"_raw": fn.get("arguments") or ""}
        tool_calls.append(
            ToolCall(id=tc.get("id") or "", name=fn.get("name") or "", arguments=args)
        )
    return LLMResponse(
        content=message.get("content") or "",
        tool_calls=tool_calls,
        finish_reason=choice.get("finish_reason") or "",
        usage=data.get("usage") or {},
    )
