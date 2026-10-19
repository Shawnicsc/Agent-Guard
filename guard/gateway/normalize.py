"""规范化：安全路径解析、URL 规范化、命令文本规范化与有界解码。

安全边界（DESIGN.md 第 8 节）：文件访问使用限定根目录的安全路径解析，
防止符号链接及路径遍历绕过。任何不能解析到已注册根之下的路径一律拒绝。
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

MAX_DECODE_BYTES = 8192

# 零宽与不可见字符（ZWSP/ZWNJ/ZWJ/BOM/C1 控制符），用于命令规范化阶段剥离
_INVISIBLE_RE = re.compile("[​‌‍⁠﻿­\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class PathResolutionError(ValueError):
    """路径无法解析到任何已注册根之下。"""


class UrlError(ValueError):
    pass


class PathResolver:
    """限定根目录的安全路径解析。

    roots: 别名 -> 宿主目录，如 {"workspace": Path("/srv/workspaces/s1")}。
    合法输入形式：
      - "workspace://relative/path"   指定根下相对路径
      - "relative/path"                落入 default_root（缺省第一个根）
    其余（绝对路径、~、..逃逸、符号链接逃逸）全部抛 PathResolutionError。
    """

    def __init__(self, roots: dict[str, Path], default_root: str | None = None) -> None:
        if not roots:
            raise ValueError("至少需要一个根目录")
        self.roots = {name: Path(p).resolve() for name, p in roots.items()}
        self.default_root = default_root or next(iter(self.roots))

    def resolve(self, path: str) -> Path:
        raw = unicodedata.normalize("NFKC", path).strip()
        if not raw:
            raise PathResolutionError("空路径")

        # 展开 ~: 沙箱语义下不存在宿主 home，一律拒绝
        if raw.startswith("~"):
            raise PathResolutionError(f"不允许展开用户目录: {path!r}")

        if "://" in raw:
            alias, _, rel = raw.partition("://")
            if alias not in self.roots:
                raise PathResolutionError(f"未注册的资源根: {alias!r}")
            if not rel or rel.startswith("/"):
                raise PathResolutionError(f"非法资源路径: {path!r}")
            base = self.roots[alias]
            rel_path = rel
        elif raw.startswith("/"):
            # 绝对路径：仅当恰好是已注册根本身时放行，其余拒绝
            p = PurePosixPath(raw)
            for base in self.roots.values():
                if p == PurePosixPath(base):
                    return base
            raise PathResolutionError(f"绝对路径不在任何注册根之下: {path!r}")
        else:
            base = self.roots[self.default_root]
            rel_path = raw

        rel_parts = PurePosixPath(rel_path).parts
        if any(part == ".." for part in rel_parts):
            raise PathResolutionError(f"禁止路径遍历: {path!r}")
        candidate = base.joinpath(*rel_parts).resolve()
        base_resolved = base.resolve()
        if candidate != base_resolved and base_resolved not in candidate.parents:
            raise PathResolutionError(f"路径逃逸出注册根: {path!r}")
        return candidate

    def is_within(self, resolved: Path, alias: str) -> bool:
        base = self.roots[alias]
        return resolved == base or base in resolved.parents


_SENSITIVE_PREFIXES = (
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "/etc/cron",
    "/etc/systemd/system",
    "/root",
)


def looks_sensitive(path: str) -> bool:
    """NFKC 规范化后的敏感路径特征（B 阶段 path_under 谓词的基础）。"""
    p = unicodedata.normalize("NFKC", path).strip()
    return any(p.startswith(prefix) for prefix in _SENSITIVE_PREFIXES)


def normalize_url(url: str) -> tuple[str, str]:
    """规范化 URL，返回 (host, 最终校验用 URL)。

    只允许 http/https；拒绝显式端口外的凭证注入、非常规方案；
    host 做 NFKC + 小写 + IDNA。
    """
    raw = unicodedata.normalize("NFKC", url).strip()
    if not raw:
        raise UrlError("空 URL")
    if "://" not in raw:
        raise UrlError(f"缺少 scheme: {url!r}")
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise UrlError(f"仅允许 http/https: {url!r}")
    if not parts.hostname:
        raise UrlError(f"缺少 host: {url!r}")
    if parts.username or parts.password:
        raise UrlError(f"禁止 URL 内嵌凭证: {url!r}")
    host = parts.hostname.encode("idna").decode().lower()
    netloc = f"{host}:{parts.port}" if parts.port else host
    normalized = f"{parts.scheme}://{netloc}{parts.path}"
    if parts.query:
        normalized += f"?{parts.query}"
    return host, normalized


def normalize_command_text(command: str) -> str:
    """命令文本规范化：NFKC（全角转半角）+ 剥离不可见字符 + 压缩空白。

    用于 B 阶段 command_pattern 谓词匹配，必须先规范化再匹配，
    防止全角符号/零宽字符绕过（DESIGN.md 第 9 节）。
    """
    text = unicodedata.normalize("NFKC", command)
    text = _INVISIBLE_RE.sub("", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def try_base64_decode(token: str) -> bytes | None:
    """有界 base64 解码：长度超过 MAX_DECODE_BYTES 或非合法 base64 时返回 None。"""
    token = token.strip()
    if not token or len(token) > MAX_DECODE_BYTES * 2:
        return None
    try:
        return base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None


def decoded_variants(text: str) -> list[str]:
    """生成文本的有界解码变体（B 阶段 command_pattern 用）：
    原文 + 长 base64 片段的解码结果。解码产物按可打印文本处理。"""
    variants = [text]
    for match in re.finditer(r"[A-Za-z0-9+/=]{24,}", text):
        data = try_base64_decode(match.group())
        if data and all(32 <= b < 127 or b in (9, 10, 13) for b in data):
            variants.append(normalize_command_text(data.decode()))
    return variants
