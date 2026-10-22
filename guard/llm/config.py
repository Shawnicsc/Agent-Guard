"""LLM provider 配置解析。

本地 llama.cpp server 与远程 Ark 同走 OpenAI chat completions 协议，
provider 差异只体现在 base_url / api_key / timeout / extra_body。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from guard.naming import env_value


class ProviderConfig(BaseModel):
    transport: str = "openai"
    base_url: str
    model: str
    api_key_env: str | None = None
    timeout_s: float = 60
    max_retries: int = 2
    extra_body: dict[str, Any] = Field(default_factory=dict)

    def api_key(self) -> str | None:
        if self.api_key_env is None:
            return None
        return env_value(self.api_key_env)


class ProvidersFile(BaseModel):
    default: str
    providers: dict[str, ProviderConfig]


def load_providers(path: Path) -> ProvidersFile:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return ProvidersFile.model_validate(data)


def resolve_provider(
    providers_file: ProvidersFile,
    override: str | None = None,
) -> tuple[str, ProviderConfig]:
    """选择 provider：显式 override > 配置 default。返回 (名字, 配置)。"""
    name = override or providers_file.default
    if name not in providers_file.providers:
        raise ValueError(f"未知 LLM provider: {name!r}，可选: {sorted(providers_file.providers)}")
    return name, providers_file.providers[name]
