"""结构化输出：JSON Schema 校验 + 有界重试，仍失败则标记 uncertain。

DESIGN.md 第 7 节：模型输出必须符合 JSON Schema，不合格结果重试有限次数后
标记 uncertain，交给规则保守路径。绝不接受自然语言结论驱动执行器。
"""

from __future__ import annotations

import json
import logging

from pydantic import BaseModel

from guard.llm.client import LLMClient, LLMError

log = logging.getLogger(__name__)

MAX_SCHEMA_RETRIES = 2


def structured_call[T: BaseModel](
    client: LLMClient,
    messages: list[dict],
    schema_model: type[T],
) -> tuple[T | None, str]:
    """让模型输出符合 schema_model 的 JSON。

    返回 (解析结果, 原始文本)。解析或校验失败时把错误反馈给模型重试，
    最多 MAX_SCHEMA_RETRIES 次；仍失败返回 (None, 最后一次原始文本)，
    由调用方标记 uncertain。
    """
    retry_messages = list(messages)
    last_raw = ""
    for attempt in range(MAX_SCHEMA_RETRIES + 1):
        response = client.chat(
            retry_messages,
            response_format={"type": "json_object"},
        )
        raw = response.content.strip()
        last_raw = raw
        try:
            parsed = json.loads(raw)
        except ValueError:
            log.warning("结构化输出不是合法 JSON (attempt=%d)", attempt + 1)
            retry_messages = retry_messages + [
                {"role": "assistant", "content": raw},
                {
                    "role": "user",
                    "content": "输出不是合法 JSON。请只输出一个 JSON 对象，"
                               "不要包含其他文本。",
                },
            ]
            continue
        try:
            return schema_model.model_validate(parsed), raw
        except Exception as exc:  # pydantic ValidationError
            log.warning("结构化输出未通过 Schema 校验 (attempt=%d): %s", attempt + 1, exc)
            retry_messages = retry_messages + [
                {"role": "assistant", "content": raw},
                {
                    "role": "user",
                    "content": f"JSON 未通过校验: {exc}。"
                               "请修正后重新输出符合要求的 JSON 对象。",
                },
            ]
    return None, last_raw


def structured_or_uncertain(
    client: LLMClient, messages: list[dict], fallback,
) -> tuple[object, str]:
    """structured_call 的包装：失败时返回调用方给的 uncertain 兜底值。"""
    try:
        result, raw = structured_call(client, messages, type(fallback))
    except LLMError as exc:
        log.warning("结构化调用失败，走 uncertain 兜底: %s", exc)
        return fallback, ""
    if result is None:
        return fallback, raw
    return result, raw
