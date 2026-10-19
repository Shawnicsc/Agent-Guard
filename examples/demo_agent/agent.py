#!/usr/bin/env python3
"""沙箱内演示 Agent：ReAct 循环，经 stdio JSON-lines 协议与网关通信。

纯标准库实现（沙箱镜像无第三方依赖）。LLM 与工具调用全部由沙箱外
的驱动器转发：本进程不持有网络，也不直接接触任何宿主资源。
协议见 guard/gateway/runner.py 模块注释。
"""

from __future__ import annotations

import json
import sys
import uuid

from tools import SYSTEM_PROMPT

MAX_TURNS = 25
MAX_TOOL_OUTPUT_CHARS = 8000


def send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def recv() -> dict | None:
    """读取一行并解析；EOF 返回 None；fatal 消息直接终止。"""
    line = sys.stdin.readline()
    if not line:
        return None
    msg = json.loads(line)
    if msg.get("type") == "fatal":
        print(f"[fatal] {msg.get('message', '')}", file=sys.stderr, flush=True)
        sys.exit(2)
    return msg


class DemoAgent:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def run(self) -> None:
        mission = recv()
        if mission is None or mission.get("type") != "mission":
            print("未收到初始任务消息", file=sys.stderr, flush=True)
            sys.exit(2)
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": mission.get("message", "")},
        ]
        for _turn in range(MAX_TURNS):
            request_id = str(uuid.uuid4())
            send({"type": "llm_request", "request_id": request_id, "messages": self.messages})
            response = recv()
            if response is None:
                print("驱动器关闭了管道", file=sys.stderr, flush=True)
                sys.exit(3)
            if response.get("type") != "llm_response":
                bad = response.get("type")
                print(f"预期 llm_response，收到 {bad}", file=sys.stderr, flush=True)
                sys.exit(3)

            content = response.get("content", "")
            tool_calls = response.get("tool_calls", []) or []
            if not tool_calls:
                send({"type": "done", "summary": content})
                return
            self.messages.append({
                "role": "assistant",
                "content": content,
                "tool_calls": [
                    {
                        "id": tc.get("id") or "",
                        "type": "function",
                        "function": {
                            "name": tc.get("name", ""),
                            "arguments": json.dumps(tc.get("arguments", {}), ensure_ascii=False),
                        },
                    }
                    for tc in tool_calls
                ],
            })
            for tc in tool_calls:
                self._do_tool_call(tc)
        send({"type": "done", "summary": "达到最大轮数上限，任务中止"})

    def _do_tool_call(self, tc: dict) -> None:
        send({
            "type": "tool_call",
            "request_id": str(uuid.uuid4()),
            "tool": tc.get("name", ""),
            "arguments": tc.get("arguments", {}) or {},
        })
        result = recv()
        if result is None:
            print("等待 tool_result 时管道关闭", file=sys.stderr, flush=True)
            sys.exit(3)
        status = result.get("status", "")
        if status == "BLOCK":
            content = f"[BLOCKED] 网关拒绝该调用: {result.get('reason', '')}"
        elif result.get("ok"):
            content = result.get("output", "")
        else:
            content = f"[ERROR] {result.get('error', '') or result.get('reason', '')}"
        self.messages.append({
            "role": "tool",
            "tool_call_id": tc.get("id") or "",
            "content": content[:MAX_TOOL_OUTPUT_CHARS],
        })


if __name__ == "__main__":
    DemoAgent().run()
