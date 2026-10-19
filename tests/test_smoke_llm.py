"""真实 LLM 冒烟测试（@smoke）：本地 llama.cpp 与 Ark 各真连一次。

默认跳过；显式运行：uv run pytest -m smoke
本地服务启动：make serve-local（或 AGENT_GUARD_PROVIDER=ark 使用远程）
"""

from __future__ import annotations

import os

import pytest

from guard.llm.client import LLMClient
from guard.llm.config import load_providers, resolve_provider

pytestmark = pytest.mark.smoke


def _client(provider_name: str) -> LLMClient:
    from guard.config import settings

    providers = load_providers(settings.providers_config)
    name, provider = resolve_provider(providers, provider_name)
    return LLMClient(provider, name)


@pytest.mark.skipif(os.environ.get("AGENT_GUARD_SMOKE_LOCAL") != "1",
                    reason="显式设置 AGENT_GUARD_SMOKE_LOCAL=1 启用本地冒烟")
def test_local_llm_smoke():
    client = _client("local")
    assert client.health(), "本地 llama.cpp server 未启动（先 make serve-local）"
    response = client.chat([{"role": "user", "content": "回复两个字：收到"}])
    assert response.content.strip()


@pytest.mark.skipif(not os.environ.get("ARK_API_KEY"),
                    reason="未设置 ARK_API_KEY")
def test_ark_llm_smoke():
    client = _client("ark")
    response = client.chat([{"role": "user", "content": "回复两个字：收到"}])
    assert response.content.strip()


@pytest.mark.skipif(os.environ.get("AGENT_GUARD_SMOKE_SCENARIO") != "1",
                    reason="显式设置 AGENT_GUARD_SMOKE_SCENARIO=1 启用场景冒烟（需 Docker）")
def test_readme_scenario_smoke(tmp_path):
    """阶段 A 验收场景端到端真跑（依赖 LLM + Docker + 预拉镜像）。"""
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "examples" / "scenarios"))
    from runner import run_scenario

    rc = run_scenario(root / "examples" / "scenarios" / "a_readme.yaml")
    assert rc == 0
