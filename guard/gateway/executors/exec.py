"""受控命令执行器：只 docker exec 进任务沙箱容器。

不继承宿主凭据、无网络（容器 network=none）、非特权用户、只读根文件系统；
超时与输出长度有界。
"""

from __future__ import annotations

from guard.contracts import ToolResult
from guard.sandbox import docker

MAX_OUTPUT_CHARS = 16 * 1024
EXEC_TIMEOUT_S = 15.0


class ExecExecutor:
    def __init__(self, container_name: str) -> None:
        self.container_name = container_name

    def run(self, command: str) -> ToolResult:
        if not command.strip():
            return ToolResult(ok=False, error="空命令")
        rc, output = docker.exec_in_container(
            self.container_name, command, timeout=EXEC_TIMEOUT_S,
        )
        return ToolResult(ok=(rc == 0), output=output[:MAX_OUTPUT_CHARS], error=f"exit={rc}")
