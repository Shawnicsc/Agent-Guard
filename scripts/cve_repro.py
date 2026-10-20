#!/usr/bin/env python3
"""CVE 复现批处理：运行 examples/cve_scenarios/ 全部场景并生成报告。

用法：
  uv run python scripts/cve_repro.py             # 跑全部场景，重建审计库并生成报告
  uv run python scripts/cve_repro.py --keep-db   # 追加到既有审计库

独立工作场景（不影响默认策略与既有测试结论）：
  - 策略：policies/cve_repro.yaml（默认规则全集 + CVE 专用规则，版本 cve1）
  - 审计库：docs/cve_reproduction.db（每次运行默认重建）
  - 工作区：workspaces/cve/（每场景独立会话子目录）
  - 报告：docs/cve_reproduction_report.md + docs/cve_reproduction.json

场景为 direct 模式：不经 LLM 与 Docker，攻击载荷逐条穿过完整裁决链
（注册表/能力集 → 污点 → DSL 硬规则），断言三态决策与命中规则。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "examples" / "scenarios"))

from runner import run_direct_scenario  # noqa: E402

from guard.audit.store import AuditStore  # noqa: E402
from guard.audit.trace import rebuild_dag  # noqa: E402
from guard.config import settings  # noqa: E402
from guard.sandbox.tripwire import TripwireScanner  # noqa: E402

SCENARIO_DIR = PROJECT_ROOT / "examples" / "cve_scenarios"
DB_PATH = PROJECT_ROOT / "docs" / "cve_reproduction.db"
REPORT_PATH = PROJECT_ROOT / "docs" / "cve_reproduction_report.md"
JSON_PATH = PROJECT_ROOT / "docs" / "cve_reproduction.json"


def _call_summary(call: dict) -> dict:
    dec = call.get("decision")
    return {
        "tool": call["tool"],
        "arguments": call["arguments"],
        "decision": call.get("status"),
        "rule_ids": list(dec.rule_ids) if dec else [],
        "reason": (dec.reason if dec else call.get("error"))[:160],
        "executed": bool(call.get("executed")),
        "ok": bool(call.get("ok")),
    }


def _collect_evidence(store: AuditStore, info: dict, scanner: TripwireScanner) -> dict:
    """审计事件、注入标签、绊网信号与溯源 DAG 的证据汇总。"""
    events = store.events_by_trace(info["trace_id"])
    type_counts: dict[str, int] = {}
    labels: list[str] = []
    for row in events:
        type_counts[row["type"]] = type_counts.get(row["type"], 0) + 1
        if row["type"] == "label_attached" and row["payload_json"]:
            labels.extend(json.loads(row["payload_json"]).get("labels", []))

    tripwire_hits = []
    for call in info["call_log"]:
        if call["tool"] != "exec.run":
            continue
        for hit in scanner.scan(call["arguments"].get("command", "")):
            tripwire_hits.append({"signal": hit.signal, "rule_id": hit.rule_id,
                                  "snippet": hit.snippet})

    dag = rebuild_dag(store, info["trace_id"])
    return {
        "event_counts": type_counts,
        "injection_labels": sorted(set(labels)),
        "tripwire_signals": tripwire_hits,
        "dag": {"nodes": len(dag["nodes"]), "edges": len(dag["edges"]),
                "impacts": len(dag.get("impacts", []))},
    }


def _md_table_row(cve: dict, passed: bool, rules: list[str]) -> str:
    title = cve["title"].split("（")[0]
    return (f"| {cve['id']} | {title} | {cve['cvss'].split('（')[0]} "
            f"| {'✅ 防御成功' if passed else '❌ 失败'} | {', '.join(sorted(rules)) or '—'} |")


def write_report(results: list[dict]) -> None:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# CVE 复现测试报告",
        "",
        f"- 生成时间：{now}",
        f"- 场景目录：`examples/cve_scenarios/`（{len(results)} 个，direct 模式，确定性可重放）",
        "- 策略：`policies/cve_repro.yaml`（独立于默认策略，不影响既有测试）",
        "- 复现方式：攻击载荷逐条穿过完整裁决链（注册表/能力集 → 污点 → DSL 硬规则），"
        "断言三态决策、命中规则与执行结果；不经 LLM 与 Docker。",
        "",
        "## 一、结果概览",
        "",
        "| CVE | 名称 | CVSS | 结果 | 关键阻断规则 |",
        "| --- | --- | --- | --- | --- |",
    ]
    all_rules: set[str] = set()
    for r in results:
        rules = {rid for c in r["calls"] for rid in c["rule_ids"]}
        all_rules |= rules
        lines.append(_md_table_row(r["cve"], r["passed"], rules))
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    lines += [
        "",
        f"**通过 {passed}/{total}。**命中规则全集：{', '.join(sorted(all_rules))}。",
        "",
        "## 二、复现方法",
        "",
        "```bash",
        "make cve-repro                # 或 uv run python scripts/cve_repro.py",
        "uv run pytest tests/test_cve_scenarios.py -v   # 纳入 CI 的确定性验收",
        "```",
        "",
        "审计库 `docs/cve_reproduction.db` 保存全量事件，可用"
        " `GET /api/incidents/{trace_id}` + console 工作台查看每个场景的攻击路径 DAG。",
        "",
        "## 三、逐项详情",
        "",
    ]
    for r in results:
        cve = r["cve"]
        lines += [f"### {cve['id']} — {cve['title']}", ""]
        lines += [f"- **CVSS**：{cve['cvss']}　**发布**：{cve['published']}　"
                  f"**结果**：{'✅ 防御成功' if r['passed'] else '❌ 失败'}"]
        lines += ["- **背景**：" + " ".join(cve["background"].split())]
        lines += ["- **攻击链**："]
        lines += [f"  {i}. {step}" for i, step in enumerate(cve["attack_chain"], 1)]
        lines += ["- **防御层**："]
        lines += [f"  - {layer}" for layer in cve["defense_layers"]]
        lines += ["", "**调用记录**（网关裁决）：", "",
                  "| 工具 | 参数摘要 | 决策 | 命中规则 | 实际执行 |",
                  "| --- | --- | --- | --- | --- |"]
        for c in r["calls"]:
            args = json.dumps(c["arguments"], ensure_ascii=False)[:80]
            lines.append(f"| `{c['tool']}` | `{args}` | **{c['decision']}** "
                         f"| {', '.join(c['rule_ids']) or '—'} "
                         f"| {'是' if c['executed'] else '否'} |")
        ev = r["evidence"]
        lines += ["", "**审计证据**：",
                  f"- 事件总数 {sum(ev['event_counts'].values())}"
                  f"（{', '.join(f'{k}×{v}' for k, v in sorted(ev['event_counts'].items()))}）",
                  f"- 注入/敏感标签：{', '.join(ev['injection_labels']) or '无'}",
                  f"- 溯源 DAG：{ev['dag']['nodes']} 节点 / {ev['dag']['edges']} 边"
                  f" / 影响目标 {ev['dag']['impacts']} 项"]
        if ev["tripwire_signals"]:
            signals = ", ".join(f"{h['signal']}({h['rule_id']})" for h in ev["tripwire_signals"])
            lines.append(f"- 沙箱绊网信号（TripwireScanner 复核）：{signals}")
        lines.append(f"- 参考链接：{' ; '.join(cve['references'])}")
        lines.append("")
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"报告已写入 {REPORT_PATH}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-db", action="store_true",
                        help="追加到既有审计库（默认每次重建）")
    args = parser.parse_args()

    scenarios = sorted(SCENARIO_DIR.glob("*.yaml"))
    if not scenarios:
        print(f"未找到场景文件: {SCENARIO_DIR}")
        return 2

    # 独立工作区与审计库，避免与默认运行/测试相互干扰
    settings.workspaces_root = PROJECT_ROOT / "workspaces" / "cve"
    settings.workspaces_root.mkdir(parents=True, exist_ok=True)
    if not args.keep_db and DB_PATH.exists():
        DB_PATH.unlink()
    store = AuditStore(DB_PATH)
    scanner = TripwireScanner()

    results = []
    try:
        for path in scenarios:
            scenario = yaml.safe_load(path.read_text(encoding="utf-8"))
            rc, info = run_direct_scenario(scenario, store)
            results.append({
                "id": scenario["id"],
                "cve": scenario["cve"],
                "passed": rc == 0,
                "calls": [_call_summary(c) for c in info["call_log"]],
                "failures": info["failures"],
                "evidence": _collect_evidence(store, info, scanner),
            })
    finally:
        store.close()

    JSON_PATH.write_text(json.dumps(results, ensure_ascii=False, indent=2,
                                    default=str),
                         encoding="utf-8")
    write_report(results)

    failed = [r["id"] for r in results if not r["passed"]]
    if failed:
        print(f"失败场景: {failed}")
        return 1
    print(f"全部通过: {len(results)}/{len(results)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
