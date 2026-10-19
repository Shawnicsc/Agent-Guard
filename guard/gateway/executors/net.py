"""受控网络执行器：每次请求前校验目标，跨域重定向一律拒绝。"""

from __future__ import annotations

import ipaddress
from urllib.parse import urljoin

import httpx

from guard.contracts import ContentSource, SourceType, ToolResult, content_hash
from guard.gateway.normalize import UrlError, normalize_url

MAX_BODY_BYTES = 128 * 1024
FETCH_TIMEOUT_S = 20.0
MAX_REDIRECTS = 5


class NetExecutor:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(
            timeout=FETCH_TIMEOUT_S, follow_redirects=False,
            headers={"User-Agent": "agent-guard-gateway/0.1"},
        )

    def fetch(self, url: str) -> tuple[ToolResult, ContentSource | None]:
        try:
            initial_host, normalized = normalize_url(url)
            self._check_host(initial_host)
        except UrlError as exc:
            return ToolResult(ok=False, error=f"URL 被拒绝: {exc}"), None
        try:
            for _ in range(MAX_REDIRECTS + 1):
                resp = self._client.get(normalized, follow_redirects=False)
                if resp.status_code not in {301, 302, 303, 307, 308}:
                    break
                location = resp.headers.get("location")
                if not location:
                    return ToolResult(ok=False, error="重定向缺少 Location"), None
                candidate = urljoin(normalized, location)
                host, target = normalize_url(candidate)
                self._check_host(host)
                if host != initial_host:
                    return ToolResult(ok=False, error="跨域重定向被拒绝"), None
                normalized = target
            else:
                return ToolResult(ok=False, error="重定向次数超限"), None
        except httpx.HTTPError as exc:
            return ToolResult(ok=False, error=f"网络请求失败: {exc}"), None
        except UrlError as exc:
            return ToolResult(ok=False, error=f"重定向目标被拒绝: {exc}"), None
        final = str(resp.url)
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

    @staticmethod
    def _check_host(host: str) -> None:
        """阻断 IP 字面量访问本机、内网及元数据地址；域名解析仍需网络 ACL。"""
        try:
            address = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return
        if not address.is_global:
            raise UrlError("不允许访问非公网 IP")
