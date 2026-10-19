"""按用户隔离的跨会话记忆读写；所有调用仍由 GatewaySession 裁决。"""

from __future__ import annotations

from guard.audit.store import AuditStore
from guard.contracts import ContentSource, SourceType, ToolResult, content_hash

MAX_MEMORY_CHARS = 16_384


class MemoryExecutor:
    def __init__(self, store: AuditStore, user_id: str, session_id: str) -> None:
        self.store = store
        self.user_id = user_id
        self.session_id = session_id

    def write(self, key: str, content: str) -> tuple[ToolResult, ContentSource | None]:
        if not isinstance(key, str) or not key or len(key) > 128:
            return ToolResult(ok=False, error="记忆键无效"), None
        if not isinstance(content, str) or len(content) > MAX_MEMORY_CHARS:
            return ToolResult(ok=False, error="记忆内容超出限制"), None
        prior = self.store.get_memory(self.user_id, key)
        source = ContentSource(
            type=SourceType.MEMORY, uri=f"memory://{self.user_id}/{key}",
            content_hash=content_hash(content),
            parent_source_id=prior["source_id"] if prior else None,
        )
        self.store.save_memory(self.user_id, key, content, source.source_id, self.session_id)
        return ToolResult(ok=True, output=f"已保存记忆 {key}",
                          content_source_id=source.source_id), source

    def read(self, key: str) -> tuple[ToolResult, ContentSource | None]:
        if not isinstance(key, str) or not key or len(key) > 128:
            return ToolResult(ok=False, error="记忆键无效"), None
        row = self.store.get_memory(self.user_id, key)
        if row is None:
            return ToolResult(ok=False, error=f"记忆不存在: {key}"), None
        source = ContentSource(
            type=SourceType.MEMORY, uri=f"memory://{self.user_id}/{key}",
            content_hash=content_hash(row["content"]),
            parent_source_id=row["source_id"],
        )
        return ToolResult(ok=True, output=row["content"],
                          content_source_id=source.source_id), source
