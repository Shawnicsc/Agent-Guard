"""沙箱容器管理：经 docker CLI 子进程操作（不加 docker SDK 依赖）。

守护进程不可用时由调用方降级（测试自动 skip），沙箱是硬边界而非可选项：
无法创建沙箱则任务拒绝执行。
"""

from __future__ import annotations

import shutil
import subprocess

from guard.sandbox.spec import SandboxSpec


class SandboxError(RuntimeError):
    pass


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, timeout=10,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def start_agent_container(spec: SandboxSpec) -> subprocess.Popen:
    """启动沙箱容器并返回持有 stdin/stdout 管道的进程。

    调用方（gateway.runner）通过 stdin/stdout 与容器内 Agent 做 JSON-lines 通信。
    """
    if not docker_available():
        raise SandboxError("Docker daemon 不可用，无法创建任务沙箱（拒绝执行）")
    return subprocess.Popen(
        spec.run_command(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def exec_in_container(container_name: str, command: str, timeout: float = 15.0) -> tuple[int, str]:
    """在任务容器内以非特权用户执行 shell 命令（exec 执行器唯一入口）。"""
    try:
        proc = subprocess.run(
            ["docker", "exec", "-u", "1000:1000", container_name, "sh", "-c", command],
            capture_output=True, timeout=timeout, text=True,
        )
    except subprocess.TimeoutExpired:
        return 124, f"命令执行超时（>{timeout}s）"
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output.strip()


def stop_container(container_name: str) -> None:
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        capture_output=True, timeout=15,
    )


def container_running(container_name: str) -> bool:
    result = subprocess.run(
        ["docker", "ps", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
        capture_output=True, timeout=10, text=True,
    )
    return container_name in result.stdout.split()


def probe_no_network(container_name: str) -> bool:
    """验收探针：容器内直连外网必须失败（network=none）。"""
    rc, _output = exec_in_container(
        container_name,
        "python -c \"import urllib.request; "
        "urllib.request.urlopen('http://example.com', timeout=3)\"",
        timeout=20,
    )
    return rc != 0
