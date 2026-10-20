╔══════════════════════════════════════════════════════════════════════════════╗
║  入口层                                                                      ║
║                                                                              ║
║   guard/api/routes.py                 console/（ReactFlow 调查工作台）          ║
║   （生产 REST API：会话/裁决/批准/     ← /api/incidents 攻击路径 DAG 可视化      ║
║     策略校验/事件溯源）                 scripts/（实验与复现入口 ★）              ║
║                                         agentdojo_compare · rehearsal_run      ║
║                                         rehearsal_stage3_eval                  ║
║                                         attribute_bankfull · cve_repro         ║
╚═════════════┬═════════════════════════════════┬═══════════════════════════════╝
              │                                 │
              ▼                                 ▼
╔══════════════════════════════════════════════════════════════════════════════╗
║  Agent 执行循环                                                               ║
║                                                                              ║
║   LLM（Kimi K2.6 / DeepSeek / 本地 llama.cpp Qwen3-4B，OpenAI 兼容协议）        ║
║        ⇅  请求 / 工具调用                                                      ║
║   SandboxRunner（stdio JSON-lines 驱动，子 Agent 递归派发，最大深度 2）           ║
║        ⇅  MCP 工具总线                                                        ║
║   StdioMCPProxy（stdio 中间代理：工具描述登记 TOOL_DESCRIPTION 来源、            ║
║                  返回值登记 MCP_RESPONSE 来源，部署清单校验）                    ║
╚═══════════════════┬═══════════════════════════════════════════════════════════╝
                    │  每次工具调用 → make_envelope（call_id/能力集由网关签发）
                    ▼
╔══════════════════════════════════════════════════════════════════════════════╗
║  网关裁决核心  GatewaySession.decide()          guard/gateway/session.py ★     ║
║                                                                              ║
║   ① 工具注册表 + 能力集校验              guard/gateway/registry.py             ║
║   ② 污点标签计算                        guard/taint/propagate.py             ║
║        精确/子串匹配 · 推断命中 · detect_injection → UNTRUSTED_INSTRUCTION     ║
║   ③ DSL 硬规则裁决                      guard/policy/engine.py               ║
║        policies/default.yaml（敏感路径写入 · 密钥外发 · 危险命令 ·               ║
║        越权推送/派发 · 记忆污染 · Agent 配置自我提权 · 代码注入载荷）              ║
║   ④ 语义研判（仅当硬规则未 BLOCK）         guard/semantic/analyzer.py          ║
║        LLMClient → SemanticFacts → 回填 ③ 再裁（语义无权单独放行）              ║
║   ⑤ 彩排反事实归因（rehearsal_enabled）    guard/rehearsal/service.py ★        ║
║        高危动作触发 → 工作区快照 → 低信任已读文件等长净化 →                      ║
║        隔离容器影子重跑 → 信号消失即 attributed → 回填 ③ 可 BLOCK                ║
║   三态合并： BLOCK ＞ approved_call ＞ CONFIRM ＞ ALLOW                          ║
╚═════════┬═════════════════════════════════┬═══════════════════════════════════╝
          │ BLOCK → 错误消息回传模型           │ ALLOW/已批准 → 放行执行
          │ （模型可重试）                     ▼
          │                  ┌────────────────┴────────────────┐
          │                  ▼                                 ▼
╔═════════╪══════════════════════╗  ╔══════════════════════════════════════════╗
║  执行路径 A：模拟工具 ★        ║  ║  执行路径 B：真实工具                        ║
║                              ║  ║                                            ║
║  GuardedRuntime.run_function ║  ║  executors/（fs · net · exec · git ·         ║
║  （agentdojo_compare.py）     ║  ║    memory · agent · mcp）                   ║
║  AgentDojo 模拟函数           ║  ║  exec.run 只进任务沙箱容器：                  ║
║  （内存中的假银行/Slack）     ║  ║    network=none · 只读 rootfs · cap-drop ALL ║
║                              ║  ║  执行前绊网 TripwireScanner ★（只观测）       ║
║                              ║  ║    guard/sandbox/tripwire.py                ║
║                              ║  ║    egress 客户端 · 敏感路径 · 提权 · 数据汇聚 ║
║                              ║  ║    → TRIPWIRE_HIT 审计事件                   ║
╚═════════════┬════════════════╝  ╚═════════════════════┬════════════════════════╝
              │                                             │
              └────────────────────┬────────────────────────┘
                                   ▼
╔══════════════════════════════════════════════════════════════════════════════╗
║  执行后处理（两条路径共用）                                                     ║
║                                                                              ║
║   save_source（结果内容哈希入溯源）→ 污点/注入扫描 → recent_sources(滚动6条)       ║
║        │                                          │                          ║
║        │            ┌─────────────────────────────┘                          ║
║        │            └──→ 回流到 ④，作为下次语义研判的证据 ★                        ║
║        ▼                                                                     ║
║  审计层 AuditStore (sqlite)               guard/audit/store.py                ║
║   sessions/mission_versions/sources/events/calls/decisions/                   ║
║   data_labels/approvals/policy_versions/memory_entries（11 张表）               ║
║   脱敏导出 redact.py · 链路重建 trace.rebuild_dag → DAG + 时序 + 影响范围        ║
║        │                                                                     ║
║        └──→ GET /api/incidents/{trace_id} → console/ 可视化复盘 ★               ║
╚══════════════════════════════════════════════════════════════════════════════╝
