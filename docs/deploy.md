# 部署说明（初稿）

> Agent Guard —— 面向 LLM Agent 提示注入与工具滥用的检测防御系统。
> 本文档在阶段 D 定稿；当前内容描述阶段 A（可控执行链）的部署方式。

## 1. 硬件要求

| 组件 | 最低要求 | 说明 |
| --- | --- | --- |
| CPU | x86_64，4 核 | 本地语义推理 CPU 兜底时建议 8 核+ |
| 内存 | 8 GB | 含本地 4B 量化模型加载（约 3 GB） |
| 磁盘 | 20 GB 空闲 | 模型权重约 2.5 GB，任务工作区与审计库按需增长 |
| GPU（可选） | NVIDIA CUDA 或 Intel/Radeon Vulkan | GPU 优先，无 GPU 自动回退 CPU |
| Docker | 20.10+ | 沙箱硬边界的必要条件，daemon 必须运行 |

## 2. 软件依赖

- Python 3.12（由 uv 自动管理，`scripts/` 与 `Makefile` 全部经 `uv run`）
- Docker CLI + daemon
- 本地推理：llama.cpp（`scripts/build_llamacpp.sh` 自动获取，GPU 后端自动探测：CUDA → Vulkan → CPU）

## 3. 部署步骤

### 3.1 初始化

```bash
git clone <repo> && cd agent-guard
uv sync                 # 安装依赖（Python 3.12 锁定）
```

### 3.2 本地推理服务（可选，可用远程 Ark 替代）

```bash
bash scripts/build_llamacpp.sh   # GPU 优先（CUDA/Vulkan），CPU 兜底
bash scripts/fetch_model.sh       # 下载 Qwen3-4B GGUF Q4_K_M（约 2.5 GB）
make serve-local                  # OpenAI 兼容端点 127.0.0.1:8080
```

### 3.3 远程 Ark provider（可选）

```bash
export ARK_API_KEY=<你的密钥>      # 密钥只经环境变量，绝不入库
# 编辑 configs/providers.yaml 的 ark.model 为你的 endpoint/model id
export AGENT_GUARD_PROVIDER=ark
```

### 3.4 启动网关 API（第三方 Agent 接入用）

```bash
uv run uvicorn guard.api.app:app --host 127.0.0.1 --port 8000
```

接口契约见 `DESIGN.md` 第 10 节；当前提供 `POST /sessions`、
`POST /tool-calls/decide`（阶段 A 桩决策）、`GET /health`。

### 3.5 运行演示验收场景

```bash
make run-demo   # a_readme（正常读取）+ a_escape（沙箱逃逸被挡）
```

Demo 默认任务模型为 Kimi、语义审计模型为 DeepSeek，`make run-demo` 从 `.env`
加载 `KIMI_API_KEY` 和 `DEEPSEEK_API_KEY`；另需 Docker daemon 与
`python:3.12-slim` 镜像。可用 `AGENT_GUARD_TASK_PROVIDER`、
`AGENT_GUARD_SEMANTIC_PROVIDER` 分别覆盖模型。保护开关为
`--protection enforce|monitor|off`，对照场景与完整命令见 [README](../README.md)。

## 4. 配置说明

- `configs/providers.yaml`：LLM provider（本地/远程统一 OpenAI 协议）。
  API / bench 使用 `AGENT_GUARD_PROVIDER`；Demo 使用独立的
  `AGENT_GUARD_TASK_PROVIDER` / `AGENT_GUARD_SEMANTIC_PROVIDER`。
- `guard/config.py`：数据库路径（默认 `agent-guard.db`，SQLite WAL）、
  工作区根目录、沙箱镜像。所有配置可经 `AGENT_GUARD_*` 环境变量覆盖。

## 5. 安全边界（当前阶段）

- 每任务一个 Docker 容器：`--network none`、`--read-only`、`--cap-drop ALL`、
  非特权 uid 1000、内存/CPU/进程数配额、tmpfs 工作区。
- 宿主凭据目录、Docker socket、审计库、策略文件不挂载进沙箱。
- Agent 与外界唯一通道是 stdio JSON-lines 驱动器；LLM 与工具调用全部经网关。
- 阶段 A 决策为桩（安全由沙箱硬边界保证）；三态策略裁决在阶段 B 交付。

## 6. 测试

```bash
make test    # 确定性回归（无 LLM、无外部依赖；Docker 测试自动探测）
make smoke   # 真实 LLM 冒烟（本地或 Ark）
```
