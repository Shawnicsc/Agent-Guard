╔══════════════════════════════════════════════════════════════════════════════╗
║  入口层                                                                      ║
║                                                                              ║
║   guard/api/routes.py                scripts/agentdojo_compare.py ★          ║
║   （生产 API 入口）                   （实验入口：直连 arm / Guard arm）        ║
╚═══════════════════┬═══════════════════════════════┬═════════════════════════╝
                    │                               │
                    ▼                               ▼
╔══════════════════════════════════════════════════════════════════════════════╗
║  Agent 执行循环                                                               ║
║                                                                              ║
║   LLM（受测模型 Kimi K2.6 ★ / 任意 OpenAI 兼容）                               ║
║        ⇅  请求 / 工具调用                                                      ║
║   ToolsExecutionLoop（AgentDojo AgentPipeline ★ / SandboxRunner 子进程）        ║
╚═══════════════════┬═══════════════════════════════════════════════════════════╝
                    │  每次工具调用 → make_envelope("mcp.call")
                    ▼
╔══════════════════════════════════════════════════════════════════════════════╗
║  网关裁决核心  GatewaySession.decide()          guard/gateway/session.py ★     ║
║                                                                              ║
║   ① 工具注册表 + 能力集校验              guard/gateway/registry.py             ║
║   ② 污点标签计算                        guard/taint/propagate.py             ║
║        精确/子串匹配 · 推断命中 · detect_injection → UNTRUSTED_INSTRUCTION     ║
║   ③ DSL 硬规则裁决                      guard/policy/engine.py               ║
║        policies/default.yaml（deny_semantic_deviation 等）                    ║
║   ④ 语义研判（仅当硬规则未 BLOCK）         guard/semantic/analyzer.py          ║
║        LLMClient → DeepSeek V4.1 Flash ★                                    ║
║        输入：任务 + 本次调用 + recent_sources(最近6条工具结果)                   ║
║        输出：结构化 facts → 回填 ③ 再裁（语义无权单独放行）                      ║
║   ⑤ 三态合并： BLOCK ＞ approved_call ＞ CONFIRM ＞ ALLOW                       ║
╚═══════════════┬═══════════════════════════════════┬═══════════════════════════╝
                │                                   │
        BLOCK → 错误消息回传模型            ALLOW → 放行执行
        （模型可重试）★                              │
                                                ┌───┴────────────────────────┐
                                                ▼                            ▼
╔═════════════════════════════╗   ╔════════════════════════════════════════════╗
║  执行路径 A：模拟工具 ★       ║   ╙  执行路径 B：真实工具（实验未跑）              ║
║                             ║                                                ║
║  GuardedRuntime.run_function║   SandboxRunner          guard/gateway/runner.py ║
║  （agentdojo_compare.py）    ║     subprocess + Docker   guard/sandbox/docker.py ║
║  AgentDojo 模拟函数          ║     子进程内工具调用 → 递归走 decide()              ║
║  （内存中的假银行/Slack）     ║                                                ║
╚═════════════┬═══════════════╝   net.py 执行器（真实网络/MCP）                    ║
              │                   subagent.py 执行器（子代理）                     ║
              │                            │                                     ║
              └────────────┬───────────────┘                                     ║
                           ▼                                                     ║
╔══════════════════════════════════════════════════════════════════════════════╗
║  执行后处理（两条路径共用）                                                     ║
║                                                                              ║
║   save_source（结果内容哈希入溯源）→ 污点扫描 → recent_sources(滚动6条)           ║
║        │                                          │                          ║
║        │            ┌─────────────────────────────┘                          ║
║        │            └──→ 回流到 ④，作为下次语义研判的证据 ★                        ║
║        ▼                                                                     ║
║  审计层 AuditStore (sqlite)               guard/audit/store.py                ║
║   events / calls / decisions / sources / labels / approvals / sessions         ║
║   脱敏导出 guard/audit/redact.py · 链路追踪 guard/audit/trace.py                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
