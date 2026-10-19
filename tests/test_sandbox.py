"""沙箱硬边界测试（DESIGN.md 第 11 节阶段 A 验收场景 2）。

直接对容器做探测断言：读宿主凭据失败、直连外网失败、非特权、只读根文件系统。
Docker daemon 不可用时自动 skip。
"""

from __future__ import annotations

import time

import pytest

from guard.config import settings
from guard.sandbox.docker import (
    container_running,
    exec_in_container,
    probe_no_network,
    start_agent_container,
    stop_container,
)
from guard.sandbox.spec import SandboxSpec

from .conftest import docker_available_or_skip

pytestmark = pytest.mark.timeout(120)


@pytest.fixture
def sandbox(tmp_path):
    docker_available_or_skip()
    spec = SandboxSpec(
        session_id=f"test-{tmp_path.name}",
        image="python:3.12-slim",
        agent_dir=settings.demo_agent_dir,
    )
    proc = start_agent_container(spec)
    try:
        # docker run 是异步的：轮询等待容器真正创建完成
        for _ in range(50):
            if container_running(spec.container_name):
                break
            time.sleep(0.2)
        else:
            stderr = proc.stderr.read() if proc.poll() is not None else "(still running)"
            raise AssertionError(f"容器未启动: {stderr}")
        yield spec
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        stop_container(spec.container_name)


def test_no_network(sandbox):
    """network=none：容器内直连外网必须失败。"""
    assert probe_no_network(sandbox.container_name)


def test_no_docker_socket(sandbox):
    """宿主 Docker socket 不挂载：容器内不可见。"""
    rc, output = exec_in_container(sandbox.container_name, "ls /var/run/docker.sock")
    assert rc != 0


def test_host_credentials_absent(sandbox):
    """宿主用户目录未挂载：容器内读不到宿主文件与凭据。"""
    rc, output = exec_in_container(
        sandbox.container_name, "ls /home 2>&1; ls /root 2>&1; cat /home/*/.ssh/id_rsa 2>&1")
    assert rc != 0
    assert "No such file" in output or "Permission" in output


def test_non_root_user(sandbox):
    rc, output = exec_in_container(sandbox.container_name, "id -u")
    assert rc == 0
    assert output.strip() == "1000"


def test_root_filesystem_readonly(sandbox):
    """根文件系统只读：向 / 写入必须失败。"""
    rc, output = exec_in_container(sandbox.container_name, "touch /pwned")
    assert rc != 0


def test_tmpfs_writable_and_small(sandbox):
    rc, output = exec_in_container(
        sandbox.container_name,
        "echo hello > /workspace/fill && cat /workspace/fill")
    assert rc == 0 and "hello" in output  # 小文件可写
    rc, output = exec_in_container(
        sandbox.container_name,
        "dd if=/dev/zero of=/workspace/fill bs=1M count=200 2>&1")
    assert rc != 0  # 超过 tmpfs 配额被拒
    assert "No space left" in output


def test_no_privileged_capabilities(sandbox):
    rc, output = exec_in_container(
        sandbox.container_name, "cat /proc/self/status | grep Cap")
    assert "CapEff:\t0000000000000000" in output
