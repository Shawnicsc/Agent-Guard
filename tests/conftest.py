"""测试夹具：临时库、mock LLM provider、Docker 探测。"""

from __future__ import annotations

import pytest

from guard.audit.store import AuditStore
from guard.gateway.session import GatewaySession
from guard.llm.client import LLMClient
from guard.llm.config import ProviderConfig
from guard.sandbox.docker import docker_available


@pytest.fixture
def store(tmp_path):
    s = AuditStore(tmp_path / "test.db")
    yield s
    s.close()


@pytest.fixture
def session(store, tmp_path):
    """不依赖 Docker 的网关会话（exec 执行器不可用，fs/net 可用）。"""
    return GatewaySession.create(
        store,
        tmp_path / "workspaces",
        user_id="test-user",
        goal="测试任务",
    )


def make_mock_llm(base_url: str = "http://llm-mock.test/v1", model: str = "test-model",
                  api_key_env: str | None = None) -> LLMClient:
    """指向假端点的客户端；配合 respx 拦截做可重放测试。"""
    return LLMClient(
        ProviderConfig(base_url=base_url, model=model, api_key_env=api_key_env, max_retries=0),
        "mock",
    )


def docker_available_or_skip():
    if not docker_available():
        pytest.skip("Docker daemon 不可用，跳过沙箱测试")
