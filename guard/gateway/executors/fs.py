"""受控文件执行器：宿主侧安全路径解析后读写任务工作区。

fs.read/fs.write 只能触达注册根（工作区）之内的路径；
宿主凭据、系统目录在 PathResolver 层即被拒绝，不存在"挂载漏出"。
"""

from __future__ import annotations

from guard.contracts import ContentSource, SourceType, ToolResult, content_hash
from guard.gateway.normalize import PathResolver

MAX_READ_BYTES = 256 * 1024


class FsExecutor:
    def __init__(self, resolver: PathResolver) -> None:
        self.resolver = resolver

    def read(self, path: str) -> tuple[ToolResult, ContentSource | None]:
        try:
            resolved = self.resolver.resolve(path)
        except ValueError as exc:
            return ToolResult(ok=False, error=f"路径被拒绝: {exc}"), None
        if not resolved.is_file():
            return ToolResult(ok=False, error=f"文件不存在: {path}"), None
        try:
            data = resolved.read_bytes()[:MAX_READ_BYTES]
        except OSError as exc:
            return ToolResult(ok=False, error=f"读取失败: {exc}"), None
        text = data.decode(errors="replace")
        source = ContentSource(
            type=SourceType.FILE,
            uri=str(resolved),
            content_hash=content_hash(text),
        )
        result = ToolResult(ok=True, output=text, content_source_id=source.source_id)
        return result, source

    def write(self, path: str, content: str) -> ToolResult:
        try:
            resolved = self.resolver.resolve(path)
        except ValueError as exc:
            return ToolResult(ok=False, error=f"路径被拒绝: {exc}")
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(content, encoding="utf-8")
        except OSError as exc:
            return ToolResult(ok=False, error=f"写入失败: {exc}")
        return ToolResult(ok=True, output=f"已写入 {path}（{len(content)} 字符）")
