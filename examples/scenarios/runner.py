#!/usr/bin/env python3
"""场景执行器：按 YAML 场景驱动沙箱 Agent 并断言结果。

用法：
  uv run python examples/scenarios/runner.py examples/scenarios/a_readme.yaml
  uv run --env-file .env python examples/scenarios/runner.py <场景> --protection off

真实 Agent 默认以 Kimi 执行任务、DeepSeek 进行语义审计，依赖 Docker。
CLI 与 TRACESHIELD_TASK_PROVIDER / SEMANTIC_PROVIDER / PROTECTION_MODE 可覆盖配置。
direct 场景直接提交网关请求；其保护断言按 enforce 模式设计。
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from guard.audit.store import AuditStore  # noqa: E402
from guard.config import settings  # noqa: E402
from guard.contracts import (  # noqa: E402
    AuditEvent,
    ContentSource,
    EventType,
    ProtectionMode,
    RunContext,
    SourceType,
    content_hash,
)
from guard.gateway.runner import SandboxRunner  # noqa: E402
from guard.gateway.session import GatewaySession  # noqa: E402
from guard.llm.client import LLMClient  # noqa: E402
from guard.llm.config import load_providers, resolve_provider  # noqa: E402
from guard.policy.approval import decide_approval  # noqa: E402
from guard.policy.dsl import compile_policy_file  # noqa: E402
from guard.policy.engine import PolicyEngine  # noqa: E402
from guard.sandbox.spec import SandboxSpec  # noqa: E402
from guard.semantic.analyzer import SemanticAnalyzer  # noqa: E402


def seed_workspace(workspace_root: Path, seed_files: dict[str, str]) -> None:
    for dest_rel, src_rel in (seed_files or {}).items():
        src = (PROJECT_ROOT / src_rel).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"种子文件不存在: {src_rel}")
        dest = workspace_root / dest_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)


def seed_content(workspace_root: Path, contents: dict[str, str]) -> None:
    """直接以 {相对路径: 文本内容} 预置工作区文件（b 场景植入密钥样本用）。"""
    for rel, content in (contents or {}).items():
        dest = workspace_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


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


def _assert_call(call: dict, entry: dict,
                 protection_mode: ProtectionMode = ProtectionMode.ENFORCE) -> list[str]:
    """单条 direct 调用的断言：期望决策、命中规则、是否实际执行。"""
    entry = {**entry, **entry.get("expect_by_protection", {}).get(protection_mode.value, {})}
    failures: list[str] = []
    decision = call.get("decision")
    action = decision.action.value if decision is not None else call.get("status")
    expect_action = entry.get("expect_decision")
    if expect_action and action != expect_action:
        failures.append(
            f"{entry['tool']} 期望决策 {expect_action}，实际 {action}"
            f"（rule_ids={decision.rule_ids if decision else None}，"
            f"reason={decision.reason[:120] if decision else None}）"
        )
        return failures
    expect_rules = entry.get("expect_rules")
    if expect_rules and decision is not None:
        missing = [r for r in expect_rules if r not in (decision.rule_ids or [])]
        if missing:
            failures.append(f"{entry['tool']} 期望命中规则 {missing}，"
                            f"实际 rule_ids={decision.rule_ids}")
    if entry.get("expect_executed") is True and not call.get("ok"):
        failures.append(f"{entry['tool']} 期望实际执行成功，实际 ok={call.get('ok')} "
                        f"error={call.get('error')}")
    if entry.get("expect_executed") is False and call.get("executed"):
        failures.append(f"{entry['tool']} 期望未实际执行，但执行器已运行")
    return failures


def _scenario_context(scenario: dict, provided: RunContext | None) -> RunContext:
    values = {**scenario.get("run_context", {}),
              **(provided.model_dump(exclude_none=True, exclude_unset=True) if provided else {})}
    if not values.get("batch_id"):
        values.setdefault("origin", "demo")
        values.setdefault("application", "scenario-runner")
    values.setdefault("case_id", scenario["id"])
    return RunContext(**values)


def run_direct_scenario(scenario: dict, store: AuditStore, *,
                        semantic_provider: str | None = None,
                        protection_mode: ProtectionMode = ProtectionMode.ENFORCE,
                        run_context: RunContext | None = None,
                        ) -> tuple[int, dict]:
    """direct 模式：直接构造调用，不启动 Docker；semantic 场景可调用研判模型。

    每条 call 结构：
      {tool, arguments, expect_decision: BLOCK|CONFIRM|ALLOW,
       expect_rules: [rule_id], expect_executed: bool}
    pre_read 可先执行读取以加载污点标签（exact_bytes）。
    scenario["policy"] 可指定相对仓库根的策略文件（如 CVE 复现场景），
    缺省用 settings.policy_file。
    返回 (退出码, {"trace_id", "session_id", "call_log", "failures"})。
    """
    mission = scenario["mission"]
    policy_engine = None
    if scenario.get("policy") and protection_mode != ProtectionMode.OFF:
        policy_engine = PolicyEngine(
            compile_policy_file(PROJECT_ROOT / scenario["policy"]))
    session = GatewaySession.create(
        store, settings.workspaces_root,
        user_id="demo-user",
        goal=mission["goal"],
        goal_category=mission.get("goal_category", "general"),
        allow_exfiltration=mission.get("allow_exfiltration", False),
        allow_push=mission.get("allow_push", False),
        policy_engine=policy_engine,
        protection_mode=protection_mode,
        run_context=_scenario_context(scenario, run_context),
    )
    seed_workspace(session.workspace_root, scenario.get("seed_files"))
    seed_content(session.workspace_root, scenario.get("seed_content"))
    if scenario.get("semantic") and protection_mode != ProtectionMode.OFF:
        providers = load_providers(settings.providers_config)
        override = semantic_provider or settings.semantic_provider
        name, provider = resolve_provider(providers, override)
        session.semantic_analyzer = SemanticAnalyzer(LLMClient(provider, name))
    # 直接模式的外部来源夹具：模拟 Agent 已经读到网页、描述或记忆。
    for entry in scenario.get("source_content") or []:
        text = entry["text"]
        source = ContentSource(type=SourceType(entry["type"]),
                               uri=entry["uri"], content_hash=content_hash(text))
        store.save_source(source)
        session.recent_sources.append((source, text))
        store.append_event(AuditEvent(
            trace_id=session.trace_id, type=EventType.SOURCE_RECORDED,
            session_id=session.mission.session_id, source_id=source.source_id,
            payload={"type": source.type.value, "uri": source.uri,
                     "fixture": True},
        ))

    call_log: list[dict] = []
    failures: list[str] = []
    approval_ids: dict[str, str] = {}  # entry id -> approval_id
    last_approval_id: str | None = None
    entries = (scenario.get("pre_read") or []) + (scenario.get("calls") or [])
    for entry in entries:
        # 批准步骤：{"approve": <entry-id|last>, "user": ..., "accept": bool}
        if "approve" in entry:
            ref = entry["approve"]
            approval_id = last_approval_id if ref == "last" else approval_ids.get(ref)
            if approval_id is None:
                failures.append(f"批准步骤引用不存在的调用: {ref!r}")
                continue
            try:
                record = decide_approval(store, approval_id,
                                         entry.get("user", mission.get("user_id", "demo-user")),
                                         entry.get("accept", True))
            except PermissionError as exc:
                if entry.get("expect_status") != "forbidden":
                    failures.append(f"批准步骤意外被拒: {exc}")
                continue
            if record is None:
                failures.append(f"批准记录不存在: {approval_id}")
                continue
            expect_status = entry.get("expect_status")
            if expect_status and record.status != expect_status:
                failures.append(f"批准 {approval_id[:12]}… 期望状态 {expect_status}，"
                                f"实际 {record.status}")
            continue

        record = {"tool": entry["tool"], "arguments": entry["arguments"],
                  "status": "BLOCK", "ok": False, "error": "", "decision": None,
                  "executed": False}
        call_log.append(record)
        try:
            envelope = session.make_envelope(entry["tool"], entry["arguments"])
        except ValueError as exc:
            if entry.get("expect_decision") == "BLOCK":
                record["error"] = str(exc)
                failures.extend(_assert_call(record, entry, protection_mode))
                continue
            failures.append(f"{entry['tool']} 调用构造意外失败: {exc}")
            continue
        decision = session.decide(envelope)
        record["decision"] = decision
        record["status"] = decision.action.value
        if decision.approval_id:
            last_approval_id = decision.approval_id
            if entry.get("id"):
                approval_ids[entry["id"]] = decision.approval_id
        result, _source = session.try_execute(envelope, decision)
        record["ok"] = result.ok
        record["error"] = result.error
        # try_execute 对 ALLOW/有效批准才进入执行器；用它近似 executed
        record["executed"] = result.ok or (
            decision.action.value == "ALLOW" and not result.error
        ) or ("已批准" in (decision.reason or ""))
        failures.extend(_assert_call(record, entry, protection_mode))

    print(f"[{scenario['id']}] direct protection={protection_mode.value} 调用记录:")
    for call in call_log:
        dec = call.get("decision")
        print(f"  {call['tool']} {str(call['arguments'])[:120]} "
              f"-> {call['status']} ok={call.get('ok')} "
              f"rules={dec.rule_ids if dec else None}")

    # 审计完整性：每条调用都有 CALL_RECEIVED + DECISION_MADE
    events = store.events_by_trace(session.trace_id)
    for call in call_log:
        dec = call.get("decision")
        if dec is None:
            continue
        types = [row["type"] for row in events if row["call_id"] == dec.call_id]
        if "call_received" not in types or "decision_made" not in types:
            failures.append(f"{call['tool']} 审计不完整（call/decision 事件缺失）: {types}")

    info = {
        "trace_id": session.trace_id,
        "session_id": session.mission.session_id,
        "call_log": call_log,
        "failures": failures,
    }
    if failures:
        print(f"[{scenario['id']}] 验收失败:")
        for f in failures:
            print(f"  - {f}")
        return 1, info
    print(f"[{scenario['id']}] 验收通过")
    return 0, info


def run_scenario(scenario_path: Path, store: AuditStore | None = None, *,
                 task_provider: str | None = None, semantic_provider: str | None = None,
                 protection_mode: ProtectionMode | None = None,
                 run_context: RunContext | None = None) -> int:
    scenario = yaml.safe_load(scenario_path.read_text())
    mission = scenario["mission"]
    mode = ProtectionMode(protection_mode or settings.protection_mode)
    run_context = _scenario_context(scenario, run_context)

    own_store = store is None
    if own_store:
        store = AuditStore(settings.db_path)

    if scenario.get("mode") == "direct":
        rc, _info = run_direct_scenario(scenario, store, semantic_provider=semantic_provider,
                                      protection_mode=mode, run_context=run_context)
        if own_store:
            store.close()
        return rc

    session = GatewaySession.create(
        store,
        settings.workspaces_root,
        user_id="demo-user",
        goal=mission["goal"],
        goal_category=mission.get("goal_category", "general"),
        allow_exfiltration=mission.get("allow_exfiltration", False),
        allow_push=mission.get("allow_push", False),
        protection_mode=mode,
        run_context=run_context,
    )
    seed_workspace(session.workspace_root, scenario.get("seed_files"))
    seed_content(session.workspace_root, scenario.get("seed_content"))

    providers = load_providers(settings.providers_config)
    override = task_provider or settings.task_provider
    name, provider = resolve_provider(providers, override)
    llm = LLMClient(provider, name)
    semantic_llm = None
    semantic_label = "disabled"
    if mode != ProtectionMode.OFF:
        semantic_name, semantic_config = resolve_provider(
            providers, semantic_provider or settings.semantic_provider)
        semantic_llm = LLMClient(semantic_config, semantic_name)
        semantic_label = f"{semantic_name}/{semantic_config.model}"

    spec = SandboxSpec(
        session_id=session.mission.session_id,
        image=settings.sandbox_image,
        agent_dir=settings.demo_agent_dir,
    )
    runner = SandboxRunner(session, llm, spec, store, semantic_llm=semantic_llm)
    print(f"[{scenario['id']}] task={name}/{provider.model} semantic={semantic_label} "
          f"protection={mode.value} "
          f"session={session.mission.session_id}")
    run_summary = runner.run(scenario.get("message", mission["goal"]))

    print(f"[{scenario['id']}] 调用记录:")
    for call in runner.call_log:
        status = "OK " if call.get("ok") else "ERR"
        print(f"  [{status}] {call['tool']} {call['arguments']} "
              f"-> {call['status']} decision={call.get('decision_status', call['status'])} "
              f"bypassed={call.get('bypassed', False)} {call['error']}")
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--task-provider", help="任务执行模型，默认 kimi")
    parser.add_argument("--semantic-provider", help="独立的语义审计模型，默认 deepseek")
    parser.add_argument("--protection", choices=[mode.value for mode in ProtectionMode],
                        help="enforce 拦截 / monitor 只审计放行 / off 关闭保护")
    parser.add_argument("--batch-id", help="关联已有运行批次")
    parser.add_argument("--dataset-id", help="数据集 ID")
    parser.add_argument("--dataset-version", help="数据集版本")
    parser.add_argument("--application", help="应用名称")
    parser.add_argument("--origin", choices=["production", "evaluation", "demo"])
    args = parser.parse_args()
    sys.exit(run_scenario(args.scenario, task_provider=args.task_provider,
                          semantic_provider=args.semantic_provider,
                          protection_mode=args.protection,
                          run_context=RunContext(**{key: value for key, value in {
                              "batch_id": args.batch_id, "dataset_id": args.dataset_id,
                              "dataset_version": args.dataset_version,
                              "application": args.application, "origin": args.origin,
                          }.items() if value is not None}) if any((args.batch_id, args.dataset_id,
                              args.dataset_version, args.application, args.origin)) else None))
