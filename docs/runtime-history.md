# 运行历史、日报与月报

历史报告默认查询控制台所连接的审计数据库，覆盖经过网关并保存审计记录的生产、评测和真实 Demo 会话。前端合成演示数据不写库，也不计入历史统计。旧 JSON 评测结果保留在单独的“评测存档”页签。

## 时间与统计口径

- 默认按日分类，可切换为按月；默认时区为 `Asia/Shanghai`，也可选择 UTC。
- 归档日期取会话开始时间。跨天运行仍归属开始当天，调用、裁决与事件数是该会话的累计记录；刷新后可能继续增加。
- 日期范围包含结束日期全天。没有调用的会话也会保留。
- 支持来源、应用、数据集 ID、批次 ID 和关键词查询；关键词匹配任务、用户、会话、链路及归属信息。
- 列表默认每页 25 条；筛选报告导出包括全部匹配会话，不受当前页限制。导出包含查询条件、时区、生成时间、分类汇总及每条会话记录。
- 子 Agent 沿用父任务会话，不作为新增任务计数；隔离影子重跑关联父会话并单独标记，默认不计入独立任务。
- 阻断、确认与放行均按裁决记录计数，不代表已验证的攻击数或攻击成功率。没有完整实验标注的生产运行不会生成攻击成功率。

## 登记运行归属和批次

`POST /sessions` 可增加 `run_context`。不传时，新会话记为生产运行，并分配独立的批次 ID；不会根据用户、任务文本或时间推测两个会话属于同一次测试。

| 字段 | 含义 |
| --- | --- |
| `origin` | `production`、`evaluation` 或 `demo` |
| `application` | 应用名称 |
| `dataset_id`、`dataset_name`、`dataset_version` | 数据集标识、名称与版本；生产任务可以为空 |
| `batch_id`、`batch_name` | 一次运行批次的标识与名称 |
| `case_id`、`attempt` | 样例标识与尝试序号，尝试序号默认 1 |
| `role`、`parent_session_id` | 主运行或影子运行及其父会话关联 |

先用 `POST /run-batches` 建立一轮测试：

```json
{
  "user_id": "operator",
  "run_context": {
    "origin": "evaluation",
    "application": "my-agent",
    "dataset_id": "my-dataset",
    "dataset_name": "我的新测试集",
    "dataset_version": "v1",
    "batch_name": "第一轮"
  }
}
```

接口返回 `batch_id`。同一轮测试创建每个会话时，传入相同的批次 ID 和各自的样例标识：

```json
{
  "user_id": "operator",
  "goal": "整理本条样例的文档",
  "run_context": {
    "batch_id": "替换为接口返回的批次ID",
    "case_id": "case-001",
    "attempt": 1
  }
}
```

会话继承该批次的来源、应用及数据集信息。重复测试同一数据集时创建新批次；重试样例时可以复用批次与 `case_id`，增加 `attempt`，每次仍有独立的会话 ID。已有批次的用户、来源、应用、数据集及版本不能被后来的会话改写，冲突返回 HTTP 409。运行归属只用于审计分类，不授予或修改工具权限。

## 查询接口

控制台只读接口：

```text
GET /api/console/history?group_by=day&timezone=Asia%2FShanghai
GET /api/console/history?group_by=month&start=2026-10-01&end=2026-10-31
GET /api/console/history?group_by=month&period=2026-10&origin=evaluation&dataset_id=my-dataset
GET /api/console/history?batch_id=批次ID&page=2&page_size=25
GET /api/console/history?search=关键词&export_all=true
```

`period` 按日使用 `YYYY-MM-DD`，按月使用 `YYYY-MM`。来源未记录的旧会话可用 `origin=unknown` 查询。接口支持 `application`、`include_shadow` 等参数；默认不包含影子会话。无审计库时返回 503，非法日期、时区或分页返回 422。

历史详情通过已有的 `/api/incidents/{trace_id}` 查看。历史查询没有“最近 200 条”的截断，较早会话也能分页查询并进入链路页面。

## 测试脚本与部署

- 场景运行器支持 YAML 的 `run_context`，以及命令行 `--origin`、`--application`、`--dataset-id`、`--dataset-version`、`--batch-id`；默认记为真实 Demo。
- CVE 批处理每次运行创建新批次，5 个场景共享该批次。默认保留既有审计库，`--keep-db` 继续兼容；`--db` 可指定共享审计库，`--batch-id` 可显式关联批次。
- 固定攻防语料保存持久化审计，默认使用配置的审计库，也可指定 `scripts/bench.py --db ...`。
- 隔离彩排、第三阶段验收和 AgentDojo 防护分支均写入运行归属与批次。未经过本项目网关的无防护分支不会被伪造为受保护运行。

例如，让新 CVE 运行直接进入部署控制台的历史报告：

```bash
.venv/bin/python scripts/cve_repro.py --db data/audit.db
.venv/bin/python console/server.py --db data/audit.db
```

**写入端与控制台必须连接同一个审计库。** 控制台不会自动合并其他目录下的数据库或任意实验 JSON；使用独立测试库时，可通过控制台 `--db` 查看该库。刷新历史报告会读取新会话和新增审计记录，不需要更改前端名称或重新构建。

旧会话缺少归属、批次时显示“未记录”，不推测补造。写入端在启动时增量建立批次表与查询索引；只读控制台查询旧库不执行建表或迁移。
