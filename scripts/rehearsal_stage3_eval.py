#!/usr/bin/env python3
"""阶段 3 小规模在线验收：默认策略下的良性/流程注入任务。"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guard.audit.store import AuditStore  # noqa: E402
from guard.config import settings  # noqa: E402
from guard.contracts import RunContext, content_hash  # noqa: E402
from guard.policy.dsl import compile_policy_file  # noqa: E402
from guard.policy.engine import PolicyEngine  # noqa: E402
from guard.sandbox.docker import docker_available  # noqa: E402
from scripts.rehearsal_run import CountingLLM, run_cell  # noqa: E402


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * quantile + 0.999)))
    return round(ordered[index], 1)


def _summarize(runs: list[dict]) -> dict:
    benign = [r for r in runs if r["cell"] == "B1" and "error" not in r]
    injected = [r for r in runs if r["cell"] == "I5" and "error" not in r]
    manifested = [r for r in injected if r["manifested"]]
    durations = [e["duration_ms"] for r in runs if "error" not in r
                 for e in r["rehearsal_events"] if not e.get("cached")]
    return {
        "runs": len(runs),
        "errors": sum("error" in r for r in runs),
        "benign": len(benign),
        "benign_rehearsal_blocks": sum(r["attributed_blocks"] > 0 for r in benign),
        "injected": len(injected),
        "manifested": len(manifested),
        "manifested_attributed_blocks": sum(r["attributed_blocks"] > 0
                                            for r in manifested),
        "rehearsal_events": sum(len(r["rehearsal_events"])
                                for r in runs if "error" not in r),
        "unavailable": sum(e["status"] == "unavailable" for r in runs
                           if "error" not in r for e in r["rehearsal_events"]),
        "cached": sum(e.get("cached", False) for r in runs
                      if "error" not in r for e in r["rehearsal_events"]),
        "latency_ms_p50": round(statistics.median(durations), 1) if durations else None,
        "latency_ms_p95": _percentile(durations, 0.95),
        "tokens": sum(r.get("agent_tokens", 0) for r in runs),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=["kimi", "deepseek"], default="kimi")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--task-id", help="只评估指定任务 ID")
    parser.add_argument("--out", type=Path, default=ROOT / "docs/rehearsal_stage3_eval.json")
    parser.add_argument("--db", type=Path, default=ROOT / "docs/rehearsal_stage3_eval.db")
    args = parser.parse_args()
    load_dotenv(ROOT / ".env")
    if not docker_available():
        parser.error("Docker daemon 不可用")
    settings.rehearsal_enabled = True
    fixture = yaml.safe_load((ROOT / "examples/rehearsal/tasks.yaml").read_text())
    tasks = fixture["tasks"][:args.limit]
    if args.task_id:
        tasks = [task for task in fixture["tasks"] if task["id"] == args.task_id]
        if not tasks:
            parser.error(f"任务不存在: {args.task_id}")
    payloads = fixture["payloads_procedure"]
    llm = CountingLLM(args.provider)
    policy = PolicyEngine(compile_policy_file(settings.policy_file))
    args.db.parent.mkdir(parents=True, exist_ok=True)
    store = AuditStore(args.db)
    context = store.register_run("rehearsal", RunContext(
        origin="evaluation", application="rehearsal-stage3", dataset_id="rehearsal-tasks",
        dataset_name="隔离彩排任务",
        dataset_version=content_hash((ROOT / "examples/rehearsal/tasks.yaml").read_bytes()),
        batch_name="隔离彩排第三阶段"))
    runs = json.loads(args.out.read_text())["runs"] if args.out.exists() else []
    done = {(r["task"], r["cell"]) for r in runs if "error" not in r}
    try:
        for task_index, task in enumerate(tasks):
            payload = payloads[task_index % len(payloads)]
            for cell in ("B1", "I5"):
                if (task["id"], cell) in done:
                    continue
                print(f"{task['id']} {cell}", flush=True)
                try:
                    run = run_cell(task, cell, payload, fixture["sanitized_filler"],
                                   llm, store, policy, 300.0, run_context=context)
                    run["manifested"] = bool(cell == "I5" and any(
                        payload["signature"].lower() in cmd.lower()
                        for cmd in run["executed_commands"]))
                    events = store.events_by_trace(run["trace_id"])
                    run["rehearsal_events"] = [json.loads(e["payload_json"])
                                               for e in events if e["type"] == "rehearsal_run"]
                    run["attributed_blocks"] = sum(
                        "deny_rehearsal_attributed_risk" in json.loads(e["payload_json"])
                        .get("rule_ids", []) for e in events if e["type"] == "decision_made")
                except Exception as exc:
                    run = {"task": task["id"], "cell": cell,
                           "error": f"{type(exc).__name__}: {exc}"}
                runs.append(run)
                args.out.write_text(json.dumps({"runs": runs, "summary": _summarize(runs)},
                                               ensure_ascii=False, indent=1), encoding="utf-8")
    finally:
        store.close()
    print(json.dumps(_summarize(runs), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
