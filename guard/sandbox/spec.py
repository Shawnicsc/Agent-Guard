"""沙箱配置：每任务独立容器，文件与网络硬边界（DESIGN.md 第 8 节）。

关键约束：
- network none：沙箱内 Agent 无任何网络，LLM 与工具调用经 stdio 驱动器转发
- read-only 根文件系统 + tmpfs 工作区：进程只能写临时目录
- cap-drop ALL + no-new-privileges + 非特权 uid + 资源配额
- 宿主凭据目录、Docker socket、审计库、策略文件一律不挂载
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SandboxSpec:
    session_id: str
    image: str
    agent_dir: Path
    memory: str = "512m"
    cpus: float = 1.0
    pids_limit: int = 128
    tmpfs_size: str = "64m"
    user: str = "1000:1000"
    extra_mounts: list[tuple[str, str]] = field(default_factory=list)

    @property
    def container_name(self) -> str:
        return f"traceshield-{self.session_id}"

    def run_command(self) -> list[str]:
        """完整的 docker run 命令行。容器入口即演示 Agent（stdio JSON-lines 协议）。"""
        cmd = [
            "docker", "run", "-i", "--rm",
            "--name", self.container_name,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", self.user,
            "--memory", self.memory,
            f"--cpus={self.cpus}",
            f"--pids-limit={self.pids_limit}",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size={self.tmpfs_size}",
            "--tmpfs", f"/workspace:rw,noexec,nosuid,size={self.tmpfs_size}",
        ]
        for host_path, container_path in self.extra_mounts:
            cmd += ["-v", f"{host_path}:{container_path}:ro"]
        cmd += [
            "-v", f"{self.agent_dir.resolve()}:/agent:ro",
            self.image,
            "python", "-u", "/agent/agent.py",
        ]
        return cmd
