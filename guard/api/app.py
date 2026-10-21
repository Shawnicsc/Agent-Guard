"""FastAPI 应用工厂：第三方 Agent 经 HTTP 接入网关的入口。

自建演示 Agent 走 stdio 驱动器（不经 HTTP）；本 API 满足
DESIGN.md 第 10 节的对外接口契约，两者共用同一套 GatewaySession 内核。
"""

from __future__ import annotations

from fastapi import FastAPI

from guard.audit.store import AuditStore
from guard.config import settings
from guard.gateway.session import _load_default_engine
from guard.llm.client import LLMClient
from guard.llm.config import load_providers, resolve_provider
from guard.semantic.analyzer import SemanticAnalyzer


def create_app() -> FastAPI:
    app = FastAPI(title="TraceShield", version="0.1.0")
    app.state.store = AuditStore(settings.db_path)
    app.state.sessions = {}  # session_id -> GatewaySession
    # 会话共享同一策略引擎实例；GET /policies 也从这里读取
    app.state.sessions_engine = _load_default_engine()

    providers = load_providers(settings.providers_config)
    _name, provider = resolve_provider(providers, settings.provider)
    app.state.llm = LLMClient(provider, _name)
    app.state.semantic_analyzer = SemanticAnalyzer(app.state.llm)

    from guard.api.routes import router

    app.include_router(router)
    return app
