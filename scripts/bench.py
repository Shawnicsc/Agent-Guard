#!/usr/bin/env python3
"""运行固定攻防语料并输出六项实测指标；攻击调用只裁决，不执行。"""

from __future__ import annotations

import argparse
import statistics
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guard.audit.store import AuditStore  # noqa: E402
from guard.audit.trace import rebuild_dag  # noqa: E402
from guard.config import settings  # noqa: E402
from guard.contracts import (  # noqa: E402
    AuditEvent,
    ContentSource,
    EventType,
    SourceType,
    content_hash,
)
from guard.gateway.session import GatewaySession  # noqa: E402
from guard.llm.client import LLMClient  # noqa: E402
from guard.llm.config import load_providers, resolve_provider  # noqa: E402
from guard.semantic.analyzer import SemanticAnalyzer  # noqa: E402


def _percentile(values: list[float], percent: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * percent)
    return ordered[index]


def _fmt_ms(value: float | None) -> str:
    return f"{value:.1f} ms" if value is not None else "无样本"


def _seed_case(session: GatewaySession, case: dict, store: AuditStore) -> list[str]:
    source_ids: list[str] = []
    for relative, text in (case.get("seed_files") or {}).items():
        target = session.workspace_root / relative
        if target.is_absolute() and session.workspace_root not in target.parents:
            raise ValueError(f"语料文件路径越界: {relative}")
        if ".." in Path(relative).parts:
            raise ValueError(f"语料文件路径越界: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    if case.get("pre_read"):
        call = session.make_envelope("fs.read", {"path": case["pre_read"]})
        decision = session.decide(call)
        result, source = session.try_execute(call, decision)
        if not result.ok or source is None:
            raise RuntimeError(f"预读取失败: {result.error}")
        source_ids.append(source.source_id)
    for entry in case.get("sources") or []:
        text = "普通背景资料。" * int(entry.get("padding_repeats", 0)) + entry["text"]
        source = ContentSource(
            type=SourceType(entry["type"]), uri=entry["uri"],
            content_hash=content_hash(text),
        )
        store.save_source(source)
        session.recent_sources.append((source, text))
        source_ids.append(source.source_id)
        store.append_event(AuditEvent(
            trace_id=session.trace_id, type=EventType.SOURCE_RECORDED,
            session_id=session.mission.session_id, source_id=source.source_id,
            payload={"type": source.type.value, "uri": source.uri,
                     "fixture": True},
        ))
    return source_ids


def run_benchmark(corpus: Path, provider_name: str | None = None) -> dict:
    cases = yaml.safe_load(corpus.read_text(encoding="utf-8"))["cases"]
    providers = load_providers(settings.providers_config)
    name, provider = resolve_provider(providers, provider_name or settings.provider)
    client = LLMClient(provider, name)
    if any(case.get("sources") for case in cases) and not client.health():
        raise RuntimeError(f"模型服务不可用: {name} {provider.base_url}")
    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="agent-guard-bench-") as temp:
        base = Path(temp)
        store = AuditStore(base / "audit.db")
        try:
            for case in cases:
                session = GatewaySession.create(
                    store, base / "workspaces", user_id="bench-user",
                    goal=case["goal"],
                    goal_category=case.get("goal_category", "general"),
                    semantic_analyzer=SemanticAnalyzer(client),
                )
                source_ids = _seed_case(session, case, store)
                envelope = session.make_envelope(case["tool"], case["arguments"])
                started = time.perf_counter()
                decision = session.decide(envelope)
                elapsed_ms = (time.perf_counter() - started) * 1000
                completed = False
                if not case["attack"] and decision.action.value == "ALLOW":
                    execution, _ = session.try_execute(envelope, decision)
                    completed = execution.ok
                graph = rebuild_dag(store, session.trace_id)
                node_ids = {node["id"] for node in graph["nodes"]}
                required = {f"session:{session.mission.session_id}",
                            f"agent:{session.agent_id}", f"call:{envelope.call_id}",
                            f"decision:{decision.decision_id}"}
                required.update(f"source:{source_id}" for source_id in source_ids)
                trace_complete = required <= node_ids
                results.append({
                    "id": case["id"], "category": case["category"],
                    "attack": case["attack"], "action": decision.action.value,
                    "rule_ids": decision.rule_ids, "completed": completed,
                    "decision_ms": elapsed_ms,
                    "model_ms": session.last_analysis_ms,
                    "trace_complete": trace_complete,
                })
        finally:
            store.close()

    attacks = [row for row in results if row["attack"]]
    normal = [row for row in results if not row["attack"]]
    rule_times = [row["decision_ms"] for row in results if row["model_ms"] is None]
    model_times = [row["model_ms"] for row in results if row["model_ms"] is not None]
    def ratio(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    return {
        "timestamp": datetime.now(UTC).isoformat(), "provider": name,
        "model": provider.model, "results": results,
        "metrics": {
            "attack_block_rate": ratio(sum(r["action"] == "BLOCK" for r in attacks),
                                       len(attacks)),
            "attack_interception_rate": ratio(
                sum(r["action"] in {"BLOCK", "CONFIRM"} for r in attacks),
                len(attacks)),
            "normal_completion_rate": ratio(sum(r["completed"] for r in normal),
                                            len(normal)),
            "false_interception_rate": ratio(
                sum(r["action"] in {"BLOCK", "CONFIRM"} for r in normal),
                len(normal)),
            "rule_p50_ms": statistics.median(rule_times) if rule_times else None,
            "rule_p95_ms": _percentile(rule_times, 0.95),
            "model_p50_ms": statistics.median(model_times) if model_times else None,
            "model_p95_ms": _percentile(model_times, 0.95),
            "trace_completeness": ratio(sum(r["trace_complete"] for r in results),
                                        len(results)),
        },
    }


def render_report(report: dict) -> str:
    metrics = report["metrics"]
    lines = [
        "# Agent Guard 对抗验证报告", "",
        f"运行时间（UTC）：{report['timestamp']}",
        f"模型：{report['provider']} / {report['model']}",
        "",
        "## 指标", "",
        "| 指标 | 实测值 | 口径 |", "| --- | ---: | --- |",
        f"| 攻击阻断率 | {metrics['attack_block_rate']:.1%} | 攻击样例中判为 BLOCK |",
        f"| 攻击拦截率 | {metrics['attack_interception_rate']:.1%} | BLOCK 或 CONFIRM |",
        f"| 正常完成率 | {metrics['normal_completion_rate']:.1%} | "
        "正常样例获 ALLOW 且工具执行成功 |",
        f"| 误拦率 | {metrics['false_interception_rate']:.1%} | 正常样例被 BLOCK 或 CONFIRM |",
        f"| 规则裁决耗时 p50 / p95 | {_fmt_ms(metrics['rule_p50_ms'])} / "
        f"{_fmt_ms(metrics['rule_p95_ms'])} | 未触发语义模型的裁决耗时 |",
        f"| 模型研判耗时 p50 / p95 | {_fmt_ms(metrics['model_p50_ms'])} / "
        f"{_fmt_ms(metrics['model_p95_ms'])} | 触发模型的响应耗时 |",
        f"| 链路还原完整率 | {metrics['trace_completeness']:.1%} | "
        "每例预期会话、Agent、调用、决策与来源节点均出现在 DAG |",
        "", "## 逐例结果", "",
        "| 样例 | 类别 | 攻击 | 决策 | 命中规则 | 完成 | 研判耗时 |",
        "| --- | --- | --- | --- | --- | --- | ---: |",
    ]
    for row in report["results"]:
        lines.append(
            f"| {row['id']} | {row['category']} | {'是' if row['attack'] else '否'} | "
            f"{row['action']} | {', '.join(row['rule_ids']) or '—'} | "
            f"{'是' if row['completed'] else '否'} | {_fmt_ms(row['model_ms'])} |"
        )
    lines += ["", "攻击样例只做执行前裁决，不实际执行危险工具。"
              "本报告只反映固定语料和当前模型，不代表未知攻击的保证效果。", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path,
                        default=ROOT / "examples/attack_corpus/cases.yaml")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/report.md")
    parser.add_argument("--provider", help="覆盖 configs/providers.yaml 中的默认 provider")
    args = parser.parse_args()
    report = run_benchmark(args.corpus, args.provider)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_report(report), encoding="utf-8")
    print(f"报告已生成: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
