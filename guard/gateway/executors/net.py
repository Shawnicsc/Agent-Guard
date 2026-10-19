"""受控网络执行器：沙箱无网络，所有联网经网关 net.fetch。

httpx 跟随重定向后校验最终目标仍为 http/https（DESIGN.md 第 8 节：
网络出口检查域名、重定向和最终目标）。信任级别与白名单收紧在 B 阶段策略实现。
"""

from __future__ import annotations

import httpx

from guard.contracts import ContentSource, SourceType, ToolResult, content_hash
from guard.gateway.normalize import UrlError, normalize_url

MAX_BODY_BYTES = 128 * 1024
FETCH_TIMEOUT_S = 20.0
MAX_REDIRECTS = 5


class NetExecutor:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(
            timeout=FETCH_TIMEOUT_S, follow_redirects=True,
            headers={"User-Agent": "agent-guard-gateway/0.1"},
        )

    def fetch(self, url: str) -> tuple[ToolResult, ContentSource | None]:
        try:
            _host, normalized = normalize_url(url)
        except UrlError as exc:
            return ToolResult(ok=False, error=f"URL 被拒绝: {exc}"), None
        try:
            resp = self._client.get(normalized)
        except httpx.HTTPError as exc:
            return ToolResult(ok=False, error=f"网络请求失败: {exc}"), None
        # 重定向后最终目标校验
        final = str(resp.url)
        try:
            normalize_url(final)
        except UrlError as exc:
            return ToolResult(ok=False, error=f"重定向最终目标被拒绝: {exc}"), None
        body = resp.text[:MAX_BODY_BYTES]
        source = ContentSource(
            type=SourceType.WEB_PAGE,
            uri=final,
            content_hash=content_hash(body),
        )
        result = ToolResult(
            ok=True,
            output=f"[HTTP {resp.status_code}] {final}\n\n{body}",
            content_source_id=source.source_id,
        )
        return result, source
