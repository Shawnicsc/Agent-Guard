"""全局配置：路径、数据库、镜像名、provider 选择。"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from guard.contracts import ProtectionMode

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENT_GUARD_")

    # 数据库（SQLite 起步，DESIGN.md 第 4 节）
    db_path: Path = PROJECT_ROOT / "agent-guard.db"
    # LLM provider 配置文件
    providers_config: Path = PROJECT_ROOT / "configs" / "providers.yaml"
    # provider 选择，环境变量 AGENT_GUARD_PROVIDER 覆盖
    provider: str = "local"
    # Demo 的任务执行与语义审计分别配置；通用 API/bench 继续使用 provider。
    task_provider: str = "kimi"
    semantic_provider: str = "deepseek"
    protection_mode: ProtectionMode = ProtectionMode.ENFORCE
    # 演示沙箱镜像（阶段 A 直接用官方 slim 基底，无需自建镜像）
    sandbox_image: str = "python:3.12-slim"
    # 任务工作区根目录（每会话一个子目录）
    workspaces_root: Path = PROJECT_ROOT / "workspaces"
    # 演示 Agent 代码目录（挂载进沙箱，只读）
    demo_agent_dir: Path = PROJECT_ROOT / "examples" / "demo_agent"
    # 策略文件
    policy_file: Path = PROJECT_ROOT / "policies" / "default.yaml"
    # 第三层总开关；关闭时不创建快照，也不发起净化重跑
    rehearsal_enabled: bool = False
    rehearsal_timeout_s: float = 30.0


settings = Settings()
