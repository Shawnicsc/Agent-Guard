"""高危调用的触发、净化重跑结果比较与可回填事实。"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from guard.contracts import RehearsalFacts, ToolCallEnvelope
from guard.gateway.normalize import normalize_command_text
from guard.sandbox.tripwire import TripwireScanner

_DELETE_RE = re.compile(
    r"(?:^|[;|&\n])\s*(?:rm\s+-[A-Za-z]*[rf][A-Za-z]*|shred\s+|truncate\s+)"
)
_SIDE_EFFECT_TOOLS = frozenset({"net.fetch", "git.push", "mcp.call", "memory.write"})
_LITERAL_OUTPUT_RE = re.compile(r"^\s*(?:echo|printf)\s", re.IGNORECASE)


@dataclass
class ReplayOutcome:
    completed: bool
    calls: list[dict]
    source_count: int
    reason: str = ""


def _signals(tool: str, arguments: dict, scanner: TripwireScanner) -> set[str]:
    if tool == "exec.run":
        command = arguments.get("command", "")
        if not isinstance(command, str):
            return set()
        signals = {hit.signal for hit in scanner.scan(command)}
        # 把拒绝原因写进报告时可能出现敏感路径字样，但没有读取该路径。
        if _LITERAL_OUTPUT_RE.match(command) and not re.search(r"[;|`$()\n]", command):
            signals.discard("sensitive_path")
        if _DELETE_RE.search(normalize_command_text(command)):
            signals.add("delete")
        return signals
    if tool in _SIDE_EFFECT_TOOLS:
        return {tool}
    return set()


def _same_external_target(tool: str, original: dict, replay: dict) -> bool:
    keys = {
        "net.fetch": ("url",),
        "git.push": ("remote", "branch"),
        "mcp.call": ("server", "name"),
        "memory.write": ("key",),
    }[tool]
    return all(original.get(key) == replay.get(key) for key in keys)


class RehearsalService:
    """调用方提供隔离重跑函数；此类不拥有真实执行器。"""

    def __init__(self, replay: Callable[[ToolCallEnvelope], ReplayOutcome],
                 scanner: TripwireScanner | None = None) -> None:
        self.replay = replay
        self.scanner = scanner or TripwireScanner()
        self._cache: dict[tuple[str, tuple[str, ...]], RehearsalFacts] = {}

    def should_rehearse(self, envelope: ToolCallEnvelope) -> bool:
        return bool(_signals(envelope.tool, envelope.arguments, self.scanner))

    def assess(self, envelope: ToolCallEnvelope,
               source_hashes: tuple[str, ...]) -> RehearsalFacts:
        started = time.monotonic()
        original_signals = _signals(envelope.tool, envelope.arguments, self.scanner)
        key = (envelope.tool + ":" + envelope.arguments_hash, source_hashes)
        if key in self._cache:
            return self._cache[key].model_copy(update={"cached": True, "duration_ms": 0.0})
        try:
            outcome = self.replay(envelope)
            replay_meta = {
                "replay_call_count": len(outcome.calls),
                "replay_tools": sorted({call.get("tool", "") for call in outcome.calls}),
            }
            if outcome.source_count == 0 or not outcome.completed:
                facts = RehearsalFacts(
                    status="unavailable", signals=sorted(original_signals),
                    source_count=outcome.source_count,
                    reason=outcome.reason or "净化来源缺失或重跑未完成",
                    **replay_meta,
                )
            else:
                replay_signals: set[str] = set()
                for call in outcome.calls:
                    if envelope.tool == "exec.run" and call.get("tool") == "exec.run":
                        replay_signals |= _signals(
                            "exec.run", call.get("arguments", {}), self.scanner)
                    elif envelope.tool == "exec.run" and call.get("tool") in {
                            "net.fetch", "git.push", "mcp.call"}:
                        # 同一出口意图可由网关外部工具实现；不能误判为已消失。
                        replay_signals.add("egress")
                    elif call.get("tool") == envelope.tool and _same_external_target(
                            envelope.tool, envelope.arguments, call.get("arguments", {})):
                        replay_signals.add(envelope.tool)
                status = ("not_attributed" if original_signals & replay_signals
                          else "attributed")
                facts = RehearsalFacts(
                    status=status, signals=sorted(original_signals),
                    replay_signals=sorted(replay_signals),
                    source_count=outcome.source_count,
                    **replay_meta,
                )
        except Exception as exc:
            facts = RehearsalFacts(
                status="unavailable", signals=sorted(original_signals),
                reason=f"彩排失败: {type(exc).__name__}: {exc}",
            )
        facts.duration_ms = round((time.monotonic() - started) * 1000, 2)
        self._cache[key] = facts
        return facts
