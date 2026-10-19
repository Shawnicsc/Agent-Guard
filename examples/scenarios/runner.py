#!/usr/bin/env python3
"""场景执行器：按 YAML 场景驱动沙箱 Agent 并断言结果。

用法：
  uv run python examples/scenarios/runner.py examples/scenarios/a_readme.yaml
  AGENT_GUARD_PROVIDER=ark uv run python examples/scenarios/runner.py <场景>

场景为验收样例（DESIGN.md 第 11 节），依赖真实 LLM（本地 llama.cpp 或 Ark）
与 Docker；纯确定性验收在 tests/ 中完成。
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from guard.audit.store import AuditStore  # noqa: E402
from guard.config import settings  # noqa: E402
from guard.gateway.runner import SandboxRunner  # noqa: E402
from guard.gateway.session import GatewaySession  # noqa: E402
from guard.llm.client import LLMClient  # noqa: E402
from guard.llm.config import load_providers, resolve_provider  # noqa: E402
from guard.sandbox.spec import SandboxSpec  # noqa: E402


def seed_workspace(workspace_root: Path, seed_files: dict[str, str]) -> None:
    for dest_rel, src_rel in (seed_files or {}).items():
        src = (PROJECT_ROOT / src_rel).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"种子文件不存在: {src_rel}")
        dest = workspace_root / dest_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)


def check_expectations(scenario: dict, run_summary: dict, call_log: list[dict]) -> list[str]:
    """返回失败断言列表（空 = 通过）。"""
    failures: list[str] = []
    expect = scenario.get("expect") or {}

    if "completed" in expect and run_summary.get("completed") != expect["completed"]:
        failures.append(f"completed={run_summary.get('completed')}，期望 {expect['completed']}")

    ok_calls = [c for c in call_log if c.get("ok")]
    failed_calls = [c for c in call_log if not c.get("ok")]
    if "min_ok_calls" in expect and len(ok_calls) < expect["min_ok_calls"]:
        failures.append(f"成功调用数 {len(ok_calls)} < {expect['min_ok_calls']}")
    if "min_failed_calls" in expect and len(failed_calls) < expect["min_failed_calls"]:
        failures.append(f"失败调用数 {len(failed_calls)} < {expect['min_failed_calls']}")

    for tool in expect.get("must_fail_tools") or []:
        succeeded = [c for c in call_log if c["tool"] == tool and c.get("ok")]
        if succeeded:
            failures.append(f"{tool} 存在成功调用（期望全部失败）: {succeeded[0]['arguments']}")
    for tool in expect.get("must_succeed_tools") or []:
        if not any(c["tool"] == tool and c.get("ok") for c in call_log):
            failures.append(f"{tool} 没有成功调用（期望至少一次）")

    # 按命令内容精确断言：凡试图联网的 exec 命令必须失败（network=none 硬边界）
    import re

    for pattern in expect.get("must_fail_command_patterns") or []:
        matcher = re.compile(pattern)
        succeeded = [
            c for c in call_log
            if c["tool"] == "exec.run" and c.get("ok")
            and matcher.search(c["arguments"].get("command", ""))
        ]
        if succeeded:
            failures.append(
                f"exec.run 命中 /{pattern}/ 的调用成功（期望失败）: "
                f"{succeeded[0]['arguments'].get('command', '')[:100]}"
            )
    return failures


def run_scenario(scenario_path: Path, store: AuditStore | None = None) -> int:
    scenario = yaml.safe_load(scenario_path.read_text())
    mission = scenario["mission"]

    own_store = store is None
    if own_store:
        store = AuditStore(settings.db_path)

    session = GatewaySession.create(
        store,
        settings.workspaces_root,
        user_id="demo-user",
        goal=mission["goal"],
        goal_category=mission.get("goal_category", "general"),
        allow_exfiltration=mission.get("allow_exfiltration", False),
        allow_push=mission.get("allow_push", False),
    )
    seed_workspace(session.workspace_root, scenario.get("seed_files"))

    providers = load_providers(settings.providers_config)
    override = os.environ.get("AGENT_GUARD_PROVIDER") or settings.provider
    name, provider = resolve_provider(providers, override)
    llm = LLMClient(provider, name)

    spec = SandboxSpec(
        session_id=session.mission.session_id,
        image=settings.sandbox_image,
        agent_dir=settings.demo_agent_dir,
    )
    runner = SandboxRunner(session, llm, spec, store)
    print(f"[{scenario['id']}] provider={name} model={provider.model} "
          f"session={session.mission.session_id}")
    run_summary = runner.run(scenario.get("message", mission["goal"]))

    print(f"[{scenario['id']}] 调用记录:")
    for call in runner.call_log:
        status = "OK " if call.get("ok") else "ERR"
        print(f"  [{status}] {call['tool']} {call['arguments']} "
              f"-> {call['status']} {call['error']}")
    print(f"[{scenario['id']}] 完成={run_summary['completed']} "
          f"摘要: {run_summary['summary'][:300]}")

    failures = check_expectations(scenario, run_summary, runner.call_log)
    if own_store:
        store.close()
    if failures:
        print(f"[{scenario['id']}] 验收失败:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"[{scenario['id']}] 验收通过")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(run_scenario(Path(sys.argv[1])))
