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
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from guard.audit.store import AuditStore
from guard.config import settings
from guard.contracts import (
    AuditEvent,
    ContentSource,
    EventType,
    ProtectionMode,
    RunContext,
    SourceType,
    ToolResult,
    TrustLevel,
)
from guard.gateway.registry import openai_tools
from guard.gateway.session import GatewaySession
from guard.llm.client import LLMClient, LLMError
from guard.rehearsal.service import RehearsalService, ReplayOutcome
from guard.sandbox import docker
from guard.sandbox.spec import SandboxSpec
from guard.sandbox.tripwire import TripwireScanner
from guard.semantic.analyzer import SemanticAnalyzer

log = logging.getLogger(__name__)

MISSION_TIMEOUT_S = 600.0
MAX_SUBAGENT_DEPTH = 2
_RISK_LINE_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|ssh|scp|sudo|mount|unshare|base64|tar|shred|truncate)\b"
    r"|/etc/(?:shadow|sudoers)|\.ssh/|\brm\s+-|https?://",
    re.IGNORECASE,
)


class RunnerError(RuntimeError):
    pass


class SandboxRunner:
    def __init__(self, session: GatewaySession, llm: LLMClient, spec: SandboxSpec,
                 store: AuditStore, depth: int = 0, shadow: bool = False,
                 *, semantic_llm: LLMClient | None = None) -> None:
        self.session = session
        self.llm = llm
        self.spec = spec
        self.store = store
        self.depth = depth
        self.shadow = shadow
        self._snapshot: Path | None = None
        self._message = ""
        self._observed_sources: list[tuple[ContentSource, str]] = []
        # 不再用任务模型覆盖已有审计模型；调用方显式提供独立的审计客户端。
        if semantic_llm is not None and session.protection_mode != ProtectionMode.OFF:
            self.session.semantic_analyzer = SemanticAnalyzer(semantic_llm)
        # 全部调用记录（含被拒），供场景断言与测试使用
        self.call_log: list[dict] = []

    def run(self, message: str, timeout: float = MISSION_TIMEOUT_S) -> dict:
        """启动沙箱并驱动 Agent 完成一次任务，返回执行摘要。"""
        self._observed_sources = []
        snapshot_tmp = None
        prior_rehearsal = self.session.rehearsal_service
        if settings.rehearsal_enabled and not self.shadow \
                and self.session.protection_mode != ProtectionMode.OFF \
                and getattr(self.session.policy_engine, "uses_predicate",
                            lambda _name: False)("rehearsal_attributed"):
            try:
                snapshot_tmp = tempfile.TemporaryDirectory(prefix="traceshield-snapshot-")
                self._snapshot = Path(snapshot_tmp.name) / "workspace"
                shutil.copytree(self.session.workspace_root, self._snapshot, symlinks=True)
                self._message = message
                self.session.rehearsal_service = RehearsalService(self._run_sanitized)
            except OSError as exc:
                log.warning("彩排工作区快照不可用: %s", exc)
                self._snapshot = None
                self.session.rehearsal_service = RehearsalService(self._run_sanitized)
        try:
            proc = docker.start_agent_container(self.spec)
        except Exception:
            if snapshot_tmp is not None:
                snapshot_tmp.cleanup()
            self._snapshot = None
            self.session.rehearsal_service = prior_rehearsal
            raise
        from guard.gateway.executors.exec import ExecExecutor

        self.session.exec = ExecExecutor(self.spec.container_name)
        # 沙箱内命令逐条过绊网（rehearsal 阶段 2：只观测不拦截）
        if self.session.tripwire is None:
            self.session.tripwire = TripwireScanner()
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
                agent_id=self.session.agent_id,
                payload={"container": self.spec.container_name},
            ))
            auditor = (self.session.semantic_analyzer.llm
                       if self.session.semantic_analyzer is not None
                       and self.session.protection_mode != ProtectionMode.OFF else None)
            self.store.append_event(AuditEvent(
                trace_id=self.session.trace_id, type=EventType.AGENT_STARTED,
                session_id=self.session.mission.session_id,
                agent_id=self.session.agent_id,
                payload={"message": message,
                         "protection_mode": self.session.protection_mode.value,
                         "task_provider": self.llm.provider_name,
                         "task_model": self.llm.provider.model,
                         "semantic_provider": auditor.provider_name if auditor else None,
                         "semantic_model": auditor.provider.model if auditor else None},
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
            if snapshot_tmp is not None:
                snapshot_tmp.cleanup()
            self._snapshot = None
            self.session.rehearsal_service = prior_rehearsal
        self.store.append_event(AuditEvent(
            trace_id=self.session.trace_id, type=EventType.AGENT_DONE,
            session_id=self.session.mission.session_id,
            agent_id=self.session.agent_id,
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
            response = self.llm.chat(
                messages, tools=openai_tools(self.session.agent_capabilities))
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
        if self.shadow and tool not in {"fs.read", "fs.write", "exec.run"}:
            result = ToolResult(ok=False, error="净化副本只记录外部调用，不执行副作用")
        else:
            result, _source = self.session.try_execute(envelope, decision)
        observed = {source.source_id for source, _ in self._observed_sources}
        self._observed_sources.extend(
            (source, content) for source, content in self.session.recent_sources
            if source.source_id not in observed
        )
        if tool == "agent.spawn" and result.ok:
            if self.depth >= MAX_SUBAGENT_DEPTH:
                result = result.model_copy(update={
                    "ok": False, "error": "子 Agent 最大派发深度已达到",
                })
            else:
                child_id = json.loads(result.output)["agent_id"]
                child_session = self.session.child_session(child_id)
                if self.depth + 1 >= MAX_SUBAGENT_DEPTH:
                    child_session.agent_capabilities = frozenset(
                        capability for capability in child_session.agent_capabilities
                        if capability != "agent.spawn"
                    )
                child_spec = replace(self.spec,
                                     session_id=f"{self.spec.session_id}-{child_id}")
                child_runner = SandboxRunner(child_session, self.llm, child_spec,
                                             self.store, depth=self.depth + 1)
                child_summary = child_runner.run(arguments.get("task", ""))
                self.session.recent_sources = (self.session.recent_sources +
                                               child_session.recent_sources)[-6:]
                result = result.model_copy(update={
                    "output": json.dumps({"agent_id": child_id,
                                          "summary": child_summary}, ensure_ascii=False),
                })
        bypassed = (self.session.protection_mode == ProtectionMode.MONITOR
                    and decision.action.value != "ALLOW")
        status = "ALLOW" if bypassed else decision.action.value
        refused = not (status == "ALLOW" and result.ok)
        record.update(status=status, decision_status=decision.action.value, bypassed=bypassed,
                      ok=result.ok, error=result.error)
        self._send(proc, {
            "type": "tool_result", "request_id": request_id,
            "status": status, "decision_status": decision.action.value,
            "protection_mode": self.session.protection_mode.value,
            "ok": result.ok,
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

    def _run_sanitized(self, envelope) -> ReplayOutcome:
        """从任务起点重跑等长净化工作区，外部调用只记录不执行。"""
        if self._snapshot is None:
            return ReplayOutcome(False, [], 0, "主任务快照不可用")
        if any(Path(host).resolve() != self.session.workspace_root.resolve()
               for host, _ in self.spec.extra_mounts):
            return ReplayOutcome(False, [], 0, "工作区外挂载无法安全复制")
        with tempfile.TemporaryDirectory(prefix="traceshield-replay-") as tmp:
            root = Path(tmp)
            replay_store = AuditStore(root / "audit.db")
            try:
                replay_session = GatewaySession.create(
                    replay_store, root / "workspaces", user_id=self.session.mission.user_id,
                    goal=self.session.mission.goal,
                    goal_category=self.session.mission.goal_category.value,
                    allowed_resources=list(self.session.mission.allowed_resources),
                    allowed_actions=list(self.session.mission.allowed_actions),
                    allow_exfiltration=self.session.mission.allow_exfiltration,
                    allow_push=self.session.mission.allow_push,
                    policy_engine=self.session.policy_engine,
                    run_context=RunContext(**{**self.session.run_context, "role": "shadow",
                                             "parent_session_id": self.session.mission.session_id}),
                )
                # 彩排本身只采集候选调用，不再启动下一层彩排。
                replay_session.rehearsal_service = None
                shutil.copytree(self._snapshot, replay_session.workspace_root,
                                dirs_exist_ok=True, symlinks=True)
                changed = self._sanitize_sources(replay_session.workspace_root)
                self.store.append_event(AuditEvent(
                    trace_id=envelope.trace_id, type=EventType.REHEARSAL_STEP,
                    session_id=envelope.session_id, call_id=envelope.call_id,
                    payload={"step": "source_sanitized", "source_count": changed},
                ))
                if changed == 0:
                    return ReplayOutcome(False, [], 0, "没有可定位的低信任文件来源")
                mounts = [(str(replay_session.workspace_root), container)
                          for _, container in self.spec.extra_mounts]
                replay_spec = replace(
                    self.spec, session_id=replay_session.mission.session_id,
                    extra_mounts=mounts,
                )
                runner = SandboxRunner(replay_session, self.llm, replay_spec,
                                       replay_store, shadow=True)
                runner.session.semantic_analyzer = None
                summary = runner.run(self._message, timeout=settings.rehearsal_timeout_s)
                completed = bool(summary["completed"]) and not summary["summary"].startswith(
                    "达到最大轮数上限")
                self.store.append_event(AuditEvent(
                    trace_id=envelope.trace_id, type=EventType.REHEARSAL_STEP,
                    session_id=envelope.session_id, call_id=envelope.call_id,
                    payload={"step": "shadow_finished", "completed": completed,
                             "call_tools": [call["tool"] for call in runner.call_log],
                             "call_count": len(runner.call_log),
                             "reason": summary.get("summary", "") if not completed else ""},
                ))
                return ReplayOutcome(
                    completed,
                    [{"tool": c["tool"], "arguments": c["arguments"]}
                     for c in runner.call_log], changed,
                    summary.get("summary", "") if not completed else "",
                )
            finally:
                replay_store.close()

    def _sanitize_sources(self, replay_workspace: Path) -> int:
        """只改已进入模型上下文、且能对应到初始快照的工作区文件。"""
        source_texts = [text for source, text in
                        [*self._observed_sources, *self.session.recent_sources]
                        if source.type in {SourceType.FILE, SourceType.TOOL_RESULT}
                        and source.trust_level == TrustLevel.LOW
                        and len(text) >= 20]
        if not source_texts:
            return 0
        changed = 0
        for path in replay_workspace.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except (UnicodeError, OSError):
                continue
            if content.strip() and any(content.strip() in text for text in source_texts):
                lines = content.splitlines(keepends=True)
                sanitized = ["".join("\n" if ch == "\n" else "x" for ch in line)
                             if _RISK_LINE_RE.search(line) else line for line in lines]
                if sanitized != lines:
                    path.write_text("".join(sanitized), encoding="utf-8")
                    changed += 1
        return changed


def seed_workspace(workspace_root: Path, files: dict[str, str]) -> None:
    """按 {相对路径: 内容} 预置工作区文件。"""
    for rel, content in files.items():
        target = (workspace_root / rel).resolve()
        if workspace_root.resolve() not in target.parents and target != workspace_root.resolve():
            raise ValueError(f"种子文件逃逸工作区: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
