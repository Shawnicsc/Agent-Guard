"""SandboxRunner：沙箱 Agent 的 stdio JSON-lines 驱动器（承重协议，A 阶段冻结）。

沙箱容器 network=none、read-only；Agent 与外界唯一通道是本驱动器：
  Agent --stdout--> 驱动器 --LLM 客户端--> 模型服务（沙箱外）
  Agent --stdout--> 驱动器 --裁决+执行--> 受控工具执行器
模型输入全程经过网关，本身就是可审计证据（C/D 阶段溯源依赖）。

协议（JSON lines，一行一消息）：
  驱动器 -> Agent:
    {"type":"mission","goal":...,"message":...}
    {"type":"llm_response","request_id":...,"content":...,"tool_calls":[...]}
    {"type":"tool_result","request_id":...,"status":"ALLOW|BLOCK|CONFIRM",
     "ok":bool,"output":...,"error":...,"reason":...}
    {"type":"fatal","message":...}
  Agent -> 驱动器:
    {"type":"llm_request","request_id":...,"messages":[...]}
    {"type":"tool_call","request_id":...,"tool":...,"arguments":{...}}
    {"type":"done","summary":...}
    {"type":"error","message":...}
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path

from guard.audit.store import AuditStore
from guard.contracts import AuditEvent, EventType
from guard.gateway.registry import openai_tools
from guard.gateway.session import GatewaySession
from guard.llm.client import LLMClient, LLMError
from guard.sandbox import docker
from guard.sandbox.spec import SandboxSpec

log = logging.getLogger(__name__)

MISSION_TIMEOUT_S = 600.0


class RunnerError(RuntimeError):
    pass


class SandboxRunner:
    def __init__(self, session: GatewaySession, llm: LLMClient, spec: SandboxSpec,
                 store: AuditStore) -> None:
        self.session = session
        self.llm = llm
        self.spec = spec
        self.store = store
        # 全部调用记录（含被拒），供场景断言与测试使用
        self.call_log: list[dict] = []

    def run(self, message: str, timeout: float = MISSION_TIMEOUT_S) -> dict:
        """启动沙箱并驱动 Agent 完成一次任务，返回执行摘要。"""
        proc = docker.start_agent_container(self.spec)
        from guard.gateway.executors.exec import ExecExecutor

        self.session.exec = ExecExecutor(self.spec.container_name)
        deadline = time.monotonic() + timeout
        summary: dict = {"completed": False, "summary": "", "refused": 0}
        try:
            self._send(proc, {
                "type": "mission",
                "goal": self.session.mission.goal,
                "message": message,
            })
            self.store.append_event(AuditEvent(
                trace_id=self.session.trace_id, type=EventType.SANDBOX_STARTED,
                session_id=self.session.mission.session_id,
                payload={"container": self.spec.container_name},
            ))
            self.store.append_event(AuditEvent(
                trace_id=self.session.trace_id, type=EventType.AGENT_STARTED,
                session_id=self.session.mission.session_id,
                payload={"message": message},
            ))
            while time.monotonic() < deadline:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        raise RunnerError(f"Agent 进程提前退出 (rc={proc.returncode})")
                    break
                msg = json.loads(line)
                kind = msg.get("type")
                if kind == "llm_request":
                    self._on_llm_request(proc, msg)
                elif kind == "tool_call":
                    refused = self._on_tool_call(proc, msg)
                    summary["refused"] = summary.get("refused", 0) + refused
                elif kind == "done":
                    summary["completed"] = True
                    summary["summary"] = msg.get("summary", "")
                    break
                elif kind == "error":
                    summary["summary"] = f"Agent 报错: {msg.get('message', '')}"
                    break
                else:
                    log.warning("未知消息类型: %s", kind)
            else:
                summary["summary"] = summary.get("summary") or "任务超时"
        finally:
            self._cleanup(proc)
        self.store.append_event(AuditEvent(
            trace_id=self.session.trace_id, type=EventType.AGENT_DONE,
            session_id=self.session.mission.session_id,
            payload={"completed": summary["completed"], "summary": summary["summary"]},
        ))
        return summary

    # ---- 消息处理 ----

    def _on_llm_request(self, proc: subprocess.Popen, msg: dict) -> None:
        request_id = msg.get("request_id", "")
        messages = msg.get("messages", [])
        self.store.append_event(AuditEvent(
            trace_id=self.session.trace_id, type=EventType.LLM_REQUEST,
            session_id=self.session.mission.session_id,
            payload={"request_id": request_id, "messages": messages},
        ))
        try:
            response = self.llm.chat(messages, tools=openai_tools())
        except LLMError as exc:
            self._send(proc, {"type": "fatal", "message": f"LLM 服务不可用: {exc}"})
            return
        # OpenAI 协议的 tool_calls 直接回传，Agent 侧无差别处理
        tool_calls = [
            {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
            for tc in response.tool_calls
        ]
        self.store.append_event(AuditEvent(
            trace_id=self.session.trace_id, type=EventType.LLM_RESPONSE,
            session_id=self.session.mission.session_id,
            payload={"request_id": request_id, "content": response.content[:2000],
                     "tool_calls": tool_calls},
        ))
        self._send(proc, {
            "type": "llm_response",
            "request_id": request_id,
            "content": response.content,
            "tool_calls": tool_calls,
        })

    def _on_tool_call(self, proc: subprocess.Popen, msg: dict) -> int:
        """返回 1 表示该调用被拒绝（BLOCK 或待确认未执行）。"""
        request_id = msg.get("request_id", "")
        tool = msg.get("tool", "")
        arguments = msg.get("arguments", {}) or {}
        record = {"tool": tool, "arguments": arguments, "status": "BLOCK", "ok": False,
                  "error": "", "decision": None}
        self.call_log.append(record)
        try:
            envelope = self.session.make_envelope(tool, arguments)
        except ValueError as exc:
            record["error"] = f"调用构造被拒绝: {exc}"
            self._send(proc, {
                "type": "tool_result", "request_id": request_id,
                "status": "BLOCK", "ok": False, "reason": record["error"],
            })
            return 1
        decision = self.session.decide(envelope)
        record["decision"] = decision
        result, _source = self.session.try_execute(envelope, decision)
        refused = not (decision.action.value == "ALLOW" and result.ok)
        record.update(status=decision.action.value, ok=result.ok, error=result.error)
        self._send(proc, {
            "type": "tool_result", "request_id": request_id,
            "status": decision.action.value, "ok": result.ok,
            "output": result.output, "error": result.error,
            "reason": decision.reason, "approval_id": decision.approval_id,
        })
        return 1 if refused else 0

    # ---- 管道 ----

    def _send(self, proc: subprocess.Popen, obj: dict) -> None:
        proc.stdin.write(json.dumps(obj, ensure_ascii=False) + "\n")
        proc.stdin.flush()

    def _cleanup(self, proc: subprocess.Popen) -> None:
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        docker.stop_container(self.spec.container_name)


def seed_workspace(workspace_root: Path, files: dict[str, str]) -> None:
    """按 {相对路径: 内容} 预置工作区文件。"""
    for rel, content in files.items():
        target = (workspace_root / rel).resolve()
        if workspace_root.resolve() not in target.parents and target != workspace_root.resolve():
            raise ValueError(f"种子文件逃逸工作区: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
